# Naming conventions — why Sigyll says "Certificate Profile" and "Trust Domain"

Decided 2026-10-22 by Joe Shook after a survey of the standards, government PKI documents,
enterprise and cloud CA products, and the healthcare trust frameworks Sigyll serves.
Any future change to these names must revisit the evidence below, not just taste.

## The rules

| Sigyll concept | Name | Never call it |
|---|---|---|
| Reusable definition of what an issued certificate contains: key algorithm and size, validity, key usage, EKU, basic constraints, SAN types, CDP/AIA inclusion, RA-approval flag | **Certificate Profile** (code: `CertificateProfile`, table `CertificateProfiles`, route `/certificate-profiles`) | *Template* (Microsoft/Google/AWS vendor word; the standards say profile), *Policy* (that word means the CP/OID — see below) |
| A group of CA hierarchies under one administration, sharing the base URLs and publishing folder where their certificates and CRLs are published | **Trust Domain** (code: `TrustDomain`) | *CA pool* (Google-only; means load-balanced CAs behind one issuance endpoint), *Trust Community* (DirectTrust/UDAP term for the *organizations* that agree to a policy, not the CAs), *Realm*, *Security domain* |
| The base URLs + publishing folder inside a trust domain | **Repository** (NIST SP 800-32 "domain repository", RFC 3647 §4.2) or **Publishing** (Google "publishing options", EJBCA/OpenXPKI "publishing") | *Base URLs* as the only label |
| A root CA and the intermediates chained to it | **CA hierarchy** (universal); TEFCA says "trust chain" | — |
| A published set of trust anchors (.p7b) | **Trust Bundle** (DirectTrust, TEFCA, Direct Project) | — |
| The OID carried in `certificatePolicies` and the CP document behind it | **Certificate Policy** | *Profile* |
| String patterns such as `{BaseUrl}/crls/{CAName}.crl` or the subject DN pattern | **template** (`SubjectTemplate`, `CdpUrlTemplate`, `AiaUrlTemplate`) — a template of a *string*, not of a certificate | — |
| DID document presets | **DID Template** — not X.509, the profile vocabulary does not apply | — |

Policy vs profile is a clean split in every standard: a *certificate policy* is "a named set of rules that
indicates the applicability of a certificate to a particular community" (X.509 §3.5.15, RFC 3647, CA/B BR),
identified by an OID; a *profile* "specifies acceptable options and values from a more general document"
(NISTIR 7924 §7.1), i.e. the field and extension layout. SP 800-57 Part 3 adds that a profile "may be
implicitly specified through the certificate policy".

## Evidence 1 — standards and government PKI

| Document | Word for the issuance definition | Word for a group of CAs | Exact quote | Source |
|---|---|---|---|---|
| RFC 5280 | profile (the RFC is one) | "a user's own domain"; *trust domain* / *PKI domain* not found | "This memo profiles the X.509 v3 certificate and X.509 v2 certificate revocation list (CRL) for use in the Internet." | https://www.rfc-editor.org/rfc/rfc5280.txt |
| RFC 3647 (CP/CPS framework) | **Certificate Profile** (§4.7.1 → CP section 7.1) | PKI, "trusted domain" | "This component is used to specify the certificate format … This includes information on profiles, versions, and extensions used." / "Certificates at the start of a certification path may be considered by a relying party to be part of a trusted domain" | https://www.rfc-editor.org/rfc/rfc3647.txt |
| RFC 5914 / 6024 / 5934 | — | **trust anchor store** | "A trust anchor store is a set of one or more trust anchors stored in a device." (RFC 6024 §1.1) | https://www.rfc-editor.org/rfc/rfc6024.txt |
| RFC 4158 | — | "PKI domains" (once, in passing) | "building a path through a cross-certified environment could require the path-building module to traverse multiple PKI domains" | https://www.rfc-editor.org/rfc/rfc4158.txt |
| ITU-T X.509 (2019) | profile ("industry profiles can be defined by other standards groups") | **policy domain** (about CP OIDs, not CA groupings) | "The set of policies administered by a policy authority is called a policy domain." (§9.1) | https://www.itu.int/rec/T-REC-X.509-201910-I |
| NIST SP 800-57 Part 3 r1 | **certificate profile** | PKI | "Each PKI has its own certificate profile, identifying certificate extensions that appear in the certificates and CRLs it issues." (§2.3.3) | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57Pt3r1.pdf |
| NIST SP 800-32 (withdrawn 2021, no successor) | certificate profile ("Federal Certificate Profile") | **trust domain** — defined, 22 uses | "In the Federal context, a trust domain is a portion of the Federal PKI that operates under the management of a single policy management authority. One or more CAs exist within each trust domain. Each trust domain has a single principal CA, but may have many other CAs. Each trust domain has a domain repository." (§5.1) | https://nvlpubs.nistpubs/Legacy/SP/nistspecialpublication800-32.pdf |
| NISTIR 7924 (reference CP, draft) | **profile** ("certificate profiles or templates" as synonyms) | PKI | "That document, called a 'profile' because it specifies acceptable options and values from a more general document, is written by technical staff and often based on a standard such as [RFC 5280]." (§7.1) | https://csrc.nist.gov/CSRC/media/Publications/nistir/7924/draft/documents/nistir_7924_2nd_draft.pdf |
| NIST SP 800-130 / 800-152 | — | **security domain** (broader: any set of entities under one security policy; a PKI is the example) | "A security domain is a collection of entities, including their CKMS, in which each CKMS operates under the same security policy" (800-130 §4.9) | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-130.pdf |
| Federal PKI Common Policy Certificate & CRL Profiles v2.4 (2025) | **profile** / "Profile Worksheets" | "the Federal PKI" | "This document specifies the profiles for certificates and CRLs issued under the X.509 Certificate Policy for the U.S. Federal PKI Common Policy Framework" | https://www.idmanagement.gov/docs/fpki-x509-cert-profile-common.pdf |
| CA/Browser Forum TLS Baseline Requirements | **Certificate Profile** (defined term §1.6.1; §7.1.2.x Root CA / Subordinate CA / Subscriber Certificate Profiles) | "chain of trust" | "Certificate Profile: A set of documents or files that defines Certificate content and Certificate extensions" | https://cabforum.org/working-groups/server/baseline-requirements/requirements/ |
| SPIFFE | — | **trust domain** + **bundle** | "A SPIFFE trust domain is an identity namespace which is backed by an issuing authority with a set of cryptographic keys." | https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md |

## Evidence 2 — healthcare trust frameworks (Sigyll's own ecosystem)

| Organization / document | Issuance definition | Set of trusted CAs | Exact quote | Source |
|---|---|---|---|---|
| DirectTrust Community X.509 Certificate Policy v2.x | **Certificate Profile** (§7.1); "templates" once, as CA-ops jargon | trust anchor "bundle" | "a set of trust anchor Certificates is maintained by a relying party … MAY maintain and publish a collection of trust anchor Certificates (a 'bundle')" | https://www.maxmdirect.com.eval.max.md/documents/DirectPolicy |
| DirectTrust X.509 Certificate and CRL Profiles v2.0.1 | **Certificate Profile** per type (Issuing CA, Domain-Bound, Address-Bound, Device) | **Trust Anchor Bundle (TAB)** | "deemed normative for CA certificates submitted for inclusion in a DirectTrust Trust Anchor Bundle (TAB)" | https://www.maxmdirect.com.eval.max.md/documents/DirectTrustCertificateProfilesv2.0.1.pdf |
| DirectTrust Trust Framework page | "Trust Community Profile" = a policy set, not a certificate template | **Trust Community** (organizations), **Trust Bundle** (anchors) | "Trust Communities are formed by organizations voluntarily electing to follow a common set of standards, policies, and processes" / "A Trust Bundle is a collection of trust anchors … that meet a common set of minimum requirements expressed in a Trust Community Profile" | https://directtrust.org/what-we-do/trust-framework |
| Direct Project Applicability Statement | — | "Trusted Anchors" / "Anchor list" | "Each implementation MUST maintain an association with a supported address … and a collection of Trusted Anchors." (§4.2.3) | https://www.healthit.gov/test-method/direct-project |
| HL7 UDAP Security IG 2.0.0 | — | **trust community**; "anchor" | "A trust community is a group of member entities that has come together to support one or more interoperability use cases between its members." | https://hl7.org/fhir/us/udap-security/ |
| TEFCA QHIN Technical Framework v2.0 | "Certificate Policy" section | "root certificates issued by Certificate Authorities approved by the RCE" | — | https://rce.sequoiaproject.org/wp-content/uploads/2024/07/QTF-v2_508.pdf |
| TEFCA RCE Technical Trust Requirements (2022) | — | **RCE trust domain**; "Trust Chain"; "Trust Bundle" | "Policy Binding is the process of associating a given X.509 digital certificate to the RCE trust domain" | https://rce.sequoiaproject.org/wp-content/uploads/2022/12/Technical-Trust-Requirements.pdf |
| Carequality Technical Trust Policy v1.2 | — | **Carequality trust domain** (6 uses) | "Policy Binding is the process of associating a given X.509 digital certificate to the Carequality trust domain"; "Dual Trust Domain Considerations" | https://sequoiaproject.org/wp-content/uploads/2017/08/Carequality-Technical-Trust-Policy-Approved-6-2-2016-1.pdf |
| DirectTrust TEFCA offering | issued under "the DirectTrust Certificate Policy and the DirectTrust Certificate Profiles" | "PKI Trust List", "Sequoia Initiatives Trust Bundle" | — | https://directtrust.org/pki-trust-list |
| HL7 VhDir | — | "Digital Certificate Trust Framework" value set (direct, FPKI, SAFE-BioPharma) | — | https://hl7.org/fhir/uv/vhdir/ValueSet-digitalcertificatetrustframework.html |

"Trust circle" / "circle of trust" appears in none of these documents.

## Evidence 3 — enterprise CA products

| Product | Issuance definition | Grouping of CAs | Publication locations | Source |
|---|---|---|---|---|
| Microsoft AD CS | **Certificate templates** | "CA hierarchy" / "enterprise PKI hierarchy"; templates are forest-wide | per-CA "AIA locations and CRL distribution points" | https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts |
| Microsoft Cloud PKI (Intune) | **certificate profiles** (SCEP / trusted certificate profile) | Root CA / Issuing CA; "CA hierarchy"; the tenant | CA properties: CRL distribution point URI, AIA URI | https://learn.microsoft.com/en-us/intune/cloud-pki/configure-ca |
| EJBCA (Keyfactor) | **Certificate Profiles** + **End Entity Profiles** | none; CAs are individual objects | **Publishers**; per-CA "Default CRL Distribution Point", "CRL CA Issuer URI" | https://docs.keyfactor.com/ejbca/latest/ca-fields |
| Keyfactor Command | **Certificate templates** (imported from the source CA) | **Configuration tenant** (one AD forest or one EJBCA install) | delegated to the CA | https://software.keyfactor.com/Core-OnPrem/Current/Content/ReferenceGuide/Enrollment-Patterns.htm |
| Venafi TPP / CyberArk Certificate Manager | "CA template" (TPP); cloud renamed "issuing templates" → **request policies** | Policy Tree / folders; "CA account" | — | https://docs.venafi.cloud/vaas/issuing-templates/certificate-issuing-templates/ |
| DigiCert ONE / TLM / CA Manager | **certificate profile** | account; "hierarchy" | **Domains** ("approved domains for your OCSPs, CRLs, and AIA issuers") | https://docs.digicert.com/en/trust-lifecycle-manager/certificate-profiles.html |
| Entrust PKI Hub / PKIaaS / CA Gateway | **certificate profiles** (legacy Security Manager: "certificate types") | "n-tier PKI hierarchy" | — | https://api.managed.entrust.com/pkiaas/PKIaaS_subscriber_certificate_profiles.html |
| Sectigo Certificate Manager | **certificate profile** | "hierarchy" (root + issuing CAs) | — | https://docs.sectigo.com/scm/scm-administrator/adding-certificate-profiles |
| Nexus Certificate Manager | "certificate procedure" + "certificate format" | — | "publication procedure", "CRL procedure" | https://doc.nexusgroup.com/nexus-certificate-manager/8.13/create-certificate-procedure-in-certificate-manager |
| Red Hat Certificate System / Dogtag | **certificate profiles** | **security domain** = "a registry of PKI services" (subsystem registration, not CA grouping) | "publishing", "CRL issuing points" | https://docs.redhat.com/en/documentation/Red_Hat_Certificate_System/10/html/administration_guide/certificate_profiles |
| OpenXPKI | **certificate profile** | **PKI realm** ("a fully isolated PKI environment within an OpenXPKI instance") | realm `publishing.yaml` | https://openxpki.readthedocs.io/en/master/backend/realm.html |
| XCA (desktop) | Templates | — | — | https://hohnstaedt.de/xca-doc/html/template.html |

## Evidence 4 — cloud and open-source CAs

| Product | Issuance definition | Grouping of CAs | CRL/AIA publication config | Source |
|---|---|---|---|---|
| Google Cloud CA Service | **certificate template** (`CertificateTemplate` resource); pool-level **issuance policy** | **CA pool** ("a collection of multiple CAs with a common certificate issuance policy"; must share issuance policy, tier, location, **publishing options**) | **publishing options** (`publishCaCert`, `publishCrl`) | https://docs.cloud.google.com/certificate-authority-service/docs/ca-pool |
| AWS Private CA | **certificate template** (ARN) | "CA hierarchy" (descriptive only) | `CrlConfiguration` (S3 bucket, custom CNAME) | https://docs.aws.amazon.com/privateca/latest/userguide/UsingTemplates.html |
| Azure Key Vault | **certificate policy** | — | — | https://learn.microsoft.com/en-us/azure/key-vault/certificates/about-certificates |
| HashiCorp Vault PKI | **role** ("a procedure for generating a certificate") | mount holding **issuers** | `config/urls` (`issuing_certificates`, `crl_distribution_points`) | https://developer.hashicorp.com/vault/docs/secrets/pki/setup |
| Smallstep step-ca | **certificate template** (Go text/template) via **provisioners** | "authority" | — | https://smallstep.com/docs/step-ca/templates/ |
| cert-manager | `Certificate` resource | `Issuer` / `ClusterIssuer` | — | https://cert-manager.io/docs/concepts/issuer/ |
| CFSSL | **signing profile** | — | per profile `crl_url`, `issuer_urls` | https://github.com/cloudflare/cfssl/blob/master/doc/cmd/cfssl.txt |
| Boulder (Let's Encrypt) | **certificate profile** | **issuer** | per issuer `issuerURL`, `crlURLBase` | https://letsencrypt.org/docs/profiles/ |

## Tally

- Issuance definition: **profile** — every standard (RFC 3647, NIST 800-57 Pt 3, NISTIR 7924, FPKI, CA/B Forum) and DirectTrust, plus EJBCA, DigiCert, Entrust, Sectigo, Red Hat, OpenXPKI, Intune, Boulder, CFSSL. **template** — AD CS, Google CAS, AWS Private CA, step-ca, Keyfactor Command, XCA (the Microsoft/cloud lineage). The only government text that says "template" (NISTIR 7924) treats it as a synonym of profile.
- Grouping of CAs: no product uses "trust domain", but NIST SP 800-32, TEFCA and Carequality define it with exactly Sigyll's meaning, and SPIFFE uses it the same way today. The product terms (CA pool, realm, configuration tenant, security domain) each mean something narrower or different.

The surveys were run on 2026-10-22; quotes are verbatim from the cited pages as fetched that day.
