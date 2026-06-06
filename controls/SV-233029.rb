control 'SV-233029' do
 title 'The container platform must enforce approved authorizations for controlling the
 flow of information within the container platform based on organization-defined
 information flow control policies.'
 desc 'Controlling information flow between the container
 platform components and container user services instantiated by the container
 platform must enforce organization-defined information flow policies. Example
 methods for information flow control are using labels and separate namespace for
 containers to segregate services; user permissions and roles to limit what user
 services are available to each user; controlling the user the services are able to
 execute as; and limiting inter-container network traffic and the resources
 containers can consume. This requirement also applies to Zero Trust
 initiatives.'
 desc 'check', 'Review the container platform to determine if approved authorizations
 for controlling the flow of information within the container platform based on
 organization-defined information flow control policies is being enforced. If the
 organization-defined information flow policies are not being enforced, this is a
 finding.'
 desc 'fix', 'Configure the container platform to enforce
 approved authorizations for controlling the flow of information within the container
 platform based on organization-defined information flow control policies.'
 impact 0.5
 tag check_id: 'C-35965r601604_chk'
 tag severity: 'medium'
 tag gid: 'V-233029'
 tag rid: 'SV-233029r1137641_rule'
 tag stig_id: 'SRG-APP-000038-CTR-000105'
 tag gtitle: 'SRG-APP-000038'
 tag fix_id: 'F-35933r600575_fix'
 tag 'documentable'
 tag cci: ['CCI-001368']
 tag nist: ['AC-4']
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
