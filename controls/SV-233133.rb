control 'SV-233133' do
 title 'The container platform must generate error messages that provide information
 necessary for corrective actions without revealing information that could be
 exploited by adversaries.'
 desc 'The container platform is responsible for offering
 services to users. These services could be across diverse user groups and data
 types. To protect information about the container platform, services, users, and
 data, it is important during error message generation to offer enough information to
 diagnose the error, but not reveal information that needs to be
 protected.'
 desc 'check', 'Review documentation and logs to determine if the container platform
 writes sensitive information such as passwords or private keys into the logs and
 administrative messages. If the container platform writes sensitive or
 potentially harmful information into the logs and administrative messages, this
 is a finding.'
 desc 'fix', 'Configure the container platform to not write
 sensitive information into the logs and administrative messages.'
 impact 0.5
 tag check_id: 'C-36069r601758_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233133'
 tag rid: 'SV-233133r961167_rule'
 tag stig_id: 'SRG-APP-000266-CTR-000625'
 tag gtitle: 'SRG-APP-000266'
 tag fix_id: 'F-36037r600887_fix'
 tag 'documentable'
 tag cci: ['CCI-001312']
 tag nist: ['SI-11 a']
 tag implementation_status: 'inherited'
 tag inherited_from: 'aws-shared-responsibility'

 # AWS-managed: IAM identity internals / Fargate runtime / platform config (the cloud-provider authorization).
 ev = input('inherited_evidence_uri', value: '')
 ev = attestation_uri(:leveraged, 'aws-container-platform-authorization', ext: 'json') if ev.to_s.empty?
 max_age = input('leveraged_evidence_max_age_days', value: 365)
 impact 0.5
 if ev.to_s.empty?
 describe 'AWS-inherited authorization evidence' do
 skip 'inherited-from-aws: AWS-managed layer; set leveraged_evidence_base/inherited_evidence_uri to the cloud-provider authorization manifest, or supply a SAF attestation.'
 end
 else
 doc = document_attestation(ev, max_age_days: max_age)
 describe "AWS authorization evidence (#{ev})" do
 it('exists') { expect(doc.exists?).to eq(true) }
 it('current') { expect(doc.current?(max_age)).to eq(true) }
 end
 end
end
