control 'SV-233056' do
 title 'The container platform must protect audit information from any type of
 unauthorized read access.'
 desc 'If audit data were to become compromised, then
 competent forensic analysis and discovery of the true source of potentially
 malicious system activity is difficult if not impossible to achieve. In addition,
 access to audit records provides information an attacker could potentially use to
 his or her advantage. To ensure the veracity of audit data, the information system
 and/or the application must protect audit information from any and all unauthorized
 access. This includes read, write, and copy access. This requirement can be achieved
 through multiple methods, which will depend upon system architecture and design.
 Commonly employed methods for protecting audit information include least privilege
 permissions as well as restricting the location and number of log file repositories.
 Additionally, applications with user interfaces to audit records should not allow
 for the unfettered manipulation of or access to those records via application.
 If the application provides access to the audit data, the application becomes
 accountable for ensuring audit information is protected from unauthorized access.
 Audit information includes all information (e.g., audit records, audit settings, and
 audit reports) needed to successfully audit information system
 activity.'
 desc 'check', 'Review the container platform configuration to determine where audit
 information is stored. If the audit information is not protected from any type
 of unauthorized read access, this is a finding.'
 desc 'fix', 'Configure the container platform to protect the
 storage of audit information from unauthorized read access.'
 impact 0.5
 tag check_id: 'C-35992r600655_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233056'
 tag rid: 'SV-233056r960930_rule'
 tag stig_id: 'SRG-APP-000118-CTR-000240'
 tag gtitle: 'SRG-APP-000118'
 tag fix_id: 'F-35960r600656_fix'
 tag 'documentable'
 tag cci: ['CCI-000162']
 tag nist: ['AU-9 a']
 tag ksi:  ['KSI-MLA-OSM']
 tag nist_r4: ['AU-9']
 tag implementation_status: 'inherited'
 tag inherited_from: 'aws-shared-responsibility'

 # AWS-managed container-platform layer (runtime/host/control-plane/crypto-module/audit-
 # infra). Evidence = the leveraged the cloud-provider authorization manifest; Skip (not a
 # vacuous pass) until the consumer configures leveraged_evidence_base/inherited_evidence_uri.
 ev = input('inherited_evidence_uri', value: '')
 ev = attestation_uri(:leveraged, 'aws-container-platform-authorization', ext: 'json') if ev.to_s.empty?
 max_age = input('leveraged_evidence_max_age_days', value: 365)
 impact 0.5
 if ev.to_s.empty?
 describe 'AWS-inherited authorization evidence' do
 skip 'inherited-from-aws: AWS-managed layer; set leveraged_evidence_base / inherited_evidence_uri to the cloud-provider authorization manifest, or supply a SAF attestation.'
 end
 else
 doc = document_attestation(ev, max_age_days: max_age)
 describe "AWS authorization evidence (#{ev})" do
 it('exists') { expect(doc.exists?).to eq(true) }
 it('current') { expect(doc.current?(max_age)).to eq(true) }
 end
 end
end
