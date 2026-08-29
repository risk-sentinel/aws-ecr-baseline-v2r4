control 'SV-233273' do
 title 'Container platform components must be configured in accordance with the security
 configuration settings based on organization security configuration or implementation
 guidance, including applicable security guidance, approved configuration baselines, directives.'
 desc 'Container platform components are part of the overall
 container platform, offering services that enable the container platform to fully
 orchestrate user containers. These components may fall outside the scope of this
 document, but they still must be secured. Examples of such components are DNS,
 routers, and firewalls. These and any other services offered by the container
 platform must follow the appropriate STIG or SRG for the technology offered. If a
 STIG or SRG is not available for the technology, then best practices for the
 technology must be used. For example, the Cloud Native Computing Foundation (CNCF)
 is an open-source organization that is working on container platform best
 practices.'
 desc 'check', 'Review the container platform configuration to determine the services
 offered by the container platform and validate that any services that are
 offered are configured in accordance with the security configuration settings
 based on organization security configuration or implementation guidance, including applicable security guidance, approved configuration baselines, directives. If container platform services
 are not configured in accordance with the security configuration settings based
 on organization security configuration or implementation guidance, including applicable security guidance,
 approved configuration baselines, directives, this is a finding.'
 desc 'fix', 'Configure container services in accordance with the
 security configuration settings based on organization security configuration or
 implementation guidance, including applicable security guidance, approved configuration baselines, directives.'
 impact 0.5
 tag check_id: 'C-36209r601851_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233273'
 tag rid: 'SV-233273r961863_rule'
 tag stig_id: 'SRG-APP-000516-CTR-001325'
 tag gtitle: 'SRG-APP-000516'
 tag fix_id: 'F-36177r601307_fix'
 tag 'documentable'
 tag cci: ['CCI-000366']
 tag nist: ['CM-6 b']
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
