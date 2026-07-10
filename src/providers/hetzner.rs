/*
 * Copyright Stalwart Labs LLC See the COPYING
 * file at the top-level directory of this distribution.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use crate::{
    DnsRecord, DnsRecordType, Error, IntoFqdn,
    http::{HttpClient, HttpClientBuilder},
    utils::{
        build_caa, parse_mx, parse_srv, parse_tlsa, strip_origin_from_name, strip_trailing_dot,
        txt_chunks_to_text, unquote_txt,
    },
};
use serde::{Deserialize, Serialize};
use std::{net::AddrParseError, time::Duration};

#[derive(Clone)]
pub struct HetznerProvider {
    client: HttpClient,
    endpoint: String,
}

#[derive(Serialize, Debug)]
struct RecordsBody {
    records: Vec<RecordValue>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct RecordValue {
    value: String,
}

#[derive(Deserialize, Debug)]
struct ListRRSetsResponse {
    #[serde(default)]
    rrsets: Vec<ListedRRSet>,
}

#[derive(Deserialize, Debug)]
struct ListedRRSet {
    #[serde(rename = "type")]
    record_type: String,
    #[serde(default)]
    records: Vec<RecordValue>,
}

const DEFAULT_API_ENDPOINT: &str = "https://api.hetzner.cloud/v1";
const RETRIES: u32 = 3;

enum UpsertMode {
    Replace,
    Append,
}

impl HetznerProvider {
    pub(crate) fn new(
        api_token: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let token = api_token.as_ref();
        if token.is_empty() {
            return Err(Error::Api(
                "Hetzner API token must not be empty".to_string(),
            ));
        }

        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Bearer {token}"))
            .with_timeout(timeout)
            .build();

        Ok(Self {
            client,
            endpoint: DEFAULT_API_ENDPOINT.to_string(),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        Self {
            endpoint: endpoint.as_ref().to_string(),
            ..self
        }
    }

    pub(crate) async fn set_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));
        let values = build_values(record_type, records)?;
        self.upsert_records(
            &domain,
            &subdomain,
            record_type,
            ttl,
            values,
            UpsertMode::Replace,
        )
        .await
    }

    pub(crate) async fn add_to_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));
        let values = build_values(record_type, records)?;
        self.upsert_records(
            &domain,
            &subdomain,
            record_type,
            ttl,
            values,
            UpsertMode::Append,
        )
        .await
    }

    pub(crate) async fn remove_from_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));
        let values = build_values(record_type, records)?;
        if values.is_empty() {
            return Ok(());
        }

        let url = self.action_url(&domain, &subdomain, record_type, "remove_records");

        match self
            .client
            .post(url)
            .with_body(RecordsBody { records: values })?
            .send_with_retry::<serde_json::Value>(RETRIES)
            .await
        {
            Ok(_) => Ok(()),
            Err(Error::NotFound) => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub(crate) async fn list_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<Vec<DnsRecord>> {
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));

        let query = serde_urlencoded::to_string([
            ("name", subdomain.as_str()),
            ("type", record_type.as_str()),
            ("per_page", "50"),
        ])
        .map_err(|e| Error::Serialize(e.to_string()))?;

        let url = format!("{}/zones/{}/rrsets?{}", self.endpoint, domain, query);

        let response: ListRRSetsResponse = match self.client.get(url).send_with_retry(RETRIES).await
        {
            Ok(r) => r,
            Err(Error::NotFound) => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };

        let expected_type = record_type.as_str();
        let mut out = Vec::new();
        for rrset in response.rrsets {
            if rrset.record_type != expected_type {
                continue;
            }
            for r in rrset.records {
                out.push(parse_value(record_type, &r.value)?);
            }
        }
        Ok(out)
    }

    async fn upsert_records(
        &self,
        domain: &str,
        subdomain: &str,
        record_type: DnsRecordType,
        ttl: u32,
        values: Vec<RecordValue>,
        mode: UpsertMode,
    ) -> crate::Result<()> {
        if values.is_empty() {
            return match mode {
                UpsertMode::Replace => self.delete_rrset(domain, subdomain, record_type).await,
                UpsertMode::Append => Ok(()),
            };
        }

        let primary = match mode {
            UpsertMode::Replace => {
                self.post_set_records(domain, subdomain, record_type, &values)
                    .await
            }
            UpsertMode::Append => {
                self.post_add_records(domain, subdomain, record_type, &values)
                    .await
            }
        };

        match primary {
            Ok(_) => self.change_ttl(domain, subdomain, record_type, ttl).await,
            Err(Error::NotFound) => match mode {
                UpsertMode::Replace => {
                    self.add_records_then_change_ttl(domain, subdomain, record_type, ttl, values)
                        .await
                }
                UpsertMode::Append => {
                    self.set_records_then_change_ttl(domain, subdomain, record_type, ttl, values)
                        .await
                }
            },
            Err(e) => Err(e),
        }
    }

    async fn post_set_records(
        &self,
        domain: &str,
        subdomain: &str,
        record_type: DnsRecordType,
        values: &[RecordValue],
    ) -> crate::Result<()> {
        self.client
            .post(self.action_url(domain, subdomain, record_type, "set_records"))
            .with_body(RecordsBody {
                records: values.to_vec(),
            })?
            .send_with_retry::<serde_json::Value>(RETRIES)
            .await
            .map(|_| ())
    }

    async fn post_add_records(
        &self,
        domain: &str,
        subdomain: &str,
        record_type: DnsRecordType,
        values: &[RecordValue],
    ) -> crate::Result<()> {
        self.client
            .post(self.action_url(domain, subdomain, record_type, "add_records"))
            .with_body(RecordsBody {
                records: values.to_vec(),
            })?
            .send_with_retry::<serde_json::Value>(RETRIES)
            .await
            .map(|_| ())
    }

    async fn add_records_then_change_ttl(
        &self,
        domain: &str,
        subdomain: &str,
        record_type: DnsRecordType,
        ttl: u32,
        values: Vec<RecordValue>,
    ) -> crate::Result<()> {
        self.post_add_records(domain, subdomain, record_type, &values)
            .await?;
        self.change_ttl(domain, subdomain, record_type, ttl).await
    }

    async fn set_records_then_change_ttl(
        &self,
        domain: &str,
        subdomain: &str,
        record_type: DnsRecordType,
        ttl: u32,
        values: Vec<RecordValue>,
    ) -> crate::Result<()> {
        self.post_set_records(domain, subdomain, record_type, &values)
            .await?;
        self.change_ttl(domain, subdomain, record_type, ttl).await
    }

    async fn delete_rrset(
        &self,
        domain: &str,
        subdomain: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        match self
            .client
            .delete(self.rrset_url(domain, subdomain, record_type))
            .send_raw()
            .await
        {
            Ok(_) => Ok(()),
            Err(Error::NotFound) => Ok(()),
            Err(e) => Err(e),
        }
    }

    async fn change_ttl(
        &self,
        domain: &str,
        subdomain: &str,
        record_type: DnsRecordType,
        ttl: u32,
    ) -> crate::Result<()> {
        #[derive(Serialize)]
        struct ChangeTtl {
            ttl: u32,
        }

        self.client
            .post(self.action_url(domain, subdomain, record_type, "change_ttl"))
            .with_body(ChangeTtl { ttl })?
            .send_with_retry::<serde_json::Value>(RETRIES)
            .await
            .map(|_| ())
    }

    fn rrset_url(&self, domain: &str, subdomain: &str, record_type: DnsRecordType) -> String {
        format!(
            "{}/zones/{domain}/rrsets/{subdomain}/{}",
            self.endpoint,
            record_type.as_str()
        )
    }

    fn action_url(
        &self,
        domain: &str,
        subdomain: &str,
        record_type: DnsRecordType,
        action: &str,
    ) -> String {
        format!(
            "{}/actions/{action}",
            self.rrset_url(domain, subdomain, record_type)
        )
    }
}

fn build_values(
    expected: DnsRecordType,
    records: Vec<DnsRecord>,
) -> crate::Result<Vec<RecordValue>> {
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        if record.as_type() != expected {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                expected.as_str(),
                record.as_type().as_str(),
            )));
        }
        out.push(RecordValue {
            value: render_value(record),
        });
    }
    Ok(out)
}

fn render_value(record: DnsRecord) -> String {
    match record {
        DnsRecord::A(_) | DnsRecord::AAAA(_) | DnsRecord::TLSA(_) | DnsRecord::CAA(_) => {
            record.to_string()
        }
        DnsRecord::CNAME(content) | DnsRecord::NS(content) => content.into_fqdn().into_owned(),
        DnsRecord::MX(mx) => format!("{} {}", mx.priority, mx.exchange.into_fqdn().into_owned()),
        DnsRecord::TXT(content) => {
            let mut out = String::with_capacity(content.len() + 4);
            txt_chunks_to_text(&mut out, &content, " ");
            out
        }
        DnsRecord::SRV(srv) => format!(
            "{} {} {} {}",
            srv.priority,
            srv.weight,
            srv.port,
            srv.target.into_fqdn().into_owned(),
        ),
    }
}

fn parse_value(record_type: DnsRecordType, value: &str) -> crate::Result<DnsRecord> {
    Ok(match record_type {
        DnsRecordType::A => DnsRecord::A(value.parse().map_err(|e: AddrParseError| {
            Error::Parse(format!("invalid A value '{value}': {e}"))
        })?),
        DnsRecordType::AAAA => DnsRecord::AAAA(value.parse().map_err(|e: AddrParseError| {
            Error::Parse(format!("invalid AAAA value '{value}': {e}"))
        })?),
        DnsRecordType::CNAME => DnsRecord::CNAME(strip_trailing_dot(value).to_string()),
        DnsRecordType::NS => DnsRecord::NS(strip_trailing_dot(value).to_string()),
        DnsRecordType::MX => parse_mx(value)?,
        DnsRecordType::TXT => DnsRecord::TXT(unquote_txt(value)),
        DnsRecordType::SRV => parse_srv(value)?,
        DnsRecordType::TLSA => parse_tlsa(value)?,
        DnsRecordType::CAA => parse_caa(value)?,
    })
}

fn parse_caa(value: &str) -> crate::Result<DnsRecord> {
    let mut parts = value.splitn(3, char::is_whitespace);
    let flags: u8 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA value '{value}'")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid CAA flags in '{value}': {e}")))?;
    let tag = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA value '{value}'")))?
        .to_ascii_lowercase();
    let raw_value = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA value '{value}'")))?
        .trim();

    Ok(DnsRecord::CAA(build_caa(
        flags,
        &tag,
        &unquote_txt(raw_value),
    )?))
}
