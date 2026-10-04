//! A job: what the case asks a collector to do, signed by the analyst who
//! prepared it, so that whoever carries it to the host can't change it:
//! the plan, the keys the archive is encrypted to, and until when it may
//! run.
//!
//! ```json
//! { "sootmark_job": 1,
//!   "job": { "case": "…", "issuer": { "name": "…", "key": "<ed25519, hex>" },
//!            "issued": 1790000000, "expires": 1790604800,
//!            "recipients": ["age1…"], "plan": { "name": "…", "rules": [ … ] } },
//!   "signature": "<ed25519 over \"sootmark-job-v1\\n\" and the job's JSON, hex>" }
//! ```
//!
//! The signature covers the `job` object as written by `common::json`
//! (members in order, no spaces); it is checked against the key the job
//! names, which the operator confirms by its fingerprint.

use common::json::{self, Json};
use common::time::Ts;
use ed25519_dalek::{Signature, VerifyingKey};

use crate::plan::Plan;

/// What signatures are made over: this, then the job's JSON.
pub const SIGNED_PREFIX: &str = "sootmark-job-v1\n";
/// The format version this collector reads.
const FORMAT: i64 = 1;

/// A job whose signature and dates checked out.
#[derive(Debug, Clone)]
pub struct Job {
    /// The case it was prepared for.
    pub case: String,
    /// Who signed it.
    pub issuer: String,
    /// Their key's fingerprint (16 hex digits), to confirm with them.
    pub fingerprint: String,
    /// Until when it may run.
    pub expires: Ts,
    /// The keys the archive is encrypted to (`age1…`).
    pub recipients: Vec<String>,
    /// What to collect.
    pub plan: Plan,
}

/// Why a job was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobError(pub String);

impl Job {
    /// Read and check a job: its signature, then that `now` (Unix seconds)
    /// is within its dates.
    ///
    /// # Errors
    /// When it isn't a job, its signature doesn't verify, it has expired or
    /// isn't valid yet, or its plan is refused.
    pub fn verify(text: &str, now: i64) -> Result<Self, JobError> {
        let fail = |why: &str| JobError(why.to_owned());
        let file = json::parse(text).map_err(|_| fail("not a job: not JSON"))?;
        if file.get("sootmark_job").and_then(Json::as_i64) != Some(FORMAT) {
            return Err(fail(
                "not a Sootmark job, or a format this collector doesn't read",
            ));
        }
        let job = file.get("job").ok_or_else(|| fail("no job"))?;
        let signer = job.get("issuer").ok_or_else(|| fail("no issuer"))?;
        let key_hex = signer
            .get("key")
            .and_then(Json::as_str)
            .ok_or_else(|| fail("no issuer key"))?;
        let key = decode::<32>(key_hex)
            .and_then(|bytes| VerifyingKey::from_bytes(&bytes).ok())
            .ok_or_else(|| fail("the issuer key is not an ed25519 key"))?;
        let signature = file
            .get("signature")
            .and_then(Json::as_str)
            .and_then(decode::<64>)
            .map(|bytes| Signature::from_bytes(&bytes))
            .ok_or_else(|| fail("no signature"))?;
        let message = format!("{SIGNED_PREFIX}{job}");
        key.verify_strict(message.as_bytes(), &signature)
            .map_err(|_| {
                fail(
                    "the signature doesn't match: the job was changed, or not signed by its issuer",
                )
            })?;

        let seconds = |name: &str| {
            job.get(name)
                .and_then(Json::as_i64)
                .ok_or_else(|| fail(&format!("no {name} time")))
        };
        let (issued, expires) = (seconds("issued")?, seconds("expires")?);
        if now < issued {
            return Err(fail(
                "the job is dated in the future: check this host's clock",
            ));
        }
        if now >= expires {
            return Err(fail("the job has expired: ask the case for a new one"));
        }
        let recipients: Vec<String> = job
            .get("recipients")
            .and_then(Json::as_array)
            .unwrap_or_default()
            .iter()
            .filter_map(|r| r.as_str().map(str::to_owned))
            .collect();
        if recipients.is_empty() {
            return Err(fail("the job names no key to encrypt the archive to"));
        }
        let plan = job.get("plan").ok_or_else(|| fail("no plan"))?;
        Ok(Self {
            case: job
                .get("case")
                .and_then(Json::as_str)
                .unwrap_or_default()
                .to_owned(),
            issuer: signer
                .get("name")
                .and_then(Json::as_str)
                .unwrap_or_default()
                .to_owned(),
            fingerprint: key_hex[..16].to_owned(),
            expires: Ts::from_unix_seconds(expires),
            recipients,
            plan: Plan::parse(&plan.to_string()).map_err(|e| JobError(format!("plan: {}", e.0)))?,
        })
    }
}

/// Exactly `N` bytes from hex (either case).
fn decode<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != 2 * N {
        return None;
    }
    let digit = |b: u8| char::from(b).to_digit(16);
    let mut bytes = [0u8; N];
    for (byte, pair) in bytes.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        *byte = u8::try_from(digit(pair[0])? * 16 + digit(pair[1])?).ok()?;
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::hex;
    use ed25519_dalek::{Signer, SigningKey};

    const NOW: i64 = 1_790_000_000;

    /// A job signed by a fixed test key, `edit` applied after signing.
    fn signed(job: &Json, edit: impl FnOnce(&mut String)) -> String {
        let key = SigningKey::from_bytes(&[7; 32]);
        let signature = key.sign(format!("{SIGNED_PREFIX}{job}").as_bytes());
        let mut text = Json::object([
            ("sootmark_job", Json::from(1i64)),
            ("job", job.clone()),
            (
                "signature",
                Json::from(hex::encode(&signature.to_bytes()).as_str()),
            ),
        ])
        .to_pretty();
        edit(&mut text);
        text
    }

    fn job(expires: i64) -> Json {
        let key = hex::encode(SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes());
        json::parse(&format!(
            r#"{{"case":"case-1","issuer":{{"name":"Alice","key":"{key}"}},"issued":{},"expires":{expires},
                "recipients":["age1example"],"plan":{{"name":"p","rules":[{{"id":"mft","paths":["\\$MFT"]}}]}}}}"#,
            NOW - 60
        ))
        .unwrap()
    }

    #[test]
    fn a_signed_job_is_read() {
        let job = Job::verify(&signed(&job(NOW + 3600), |_| {}), NOW).unwrap();
        assert_eq!(
            (job.case.as_str(), job.issuer.as_str()),
            ("case-1", "Alice")
        );
        assert_eq!(job.recipients, ["age1example"]);
        assert_eq!(job.plan.rules[0].id, "mft");
        assert_eq!(job.fingerprint.len(), 16);
    }

    #[test]
    fn a_changed_or_expired_job_is_refused() {
        let changed = signed(&job(NOW + 3600), |text| {
            *text = text.replace("$MFT", "Users");
        });
        assert!(Job::verify(&changed, NOW)
            .unwrap_err()
            .0
            .contains("doesn't match"));
        let expired = signed(&job(NOW), |_| {});
        assert!(Job::verify(&expired, NOW)
            .unwrap_err()
            .0
            .contains("expired"));
        let early = signed(&job(NOW + 3600), |_| {});
        assert!(Job::verify(&early, NOW - 3600)
            .unwrap_err()
            .0
            .contains("future"));
        assert!(Job::verify("{}", NOW)
            .unwrap_err()
            .0
            .contains("not a Sootmark job"));
    }
}
