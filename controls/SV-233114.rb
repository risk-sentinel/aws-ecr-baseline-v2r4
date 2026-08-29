control 'SV-233114' do
 title 'The container platform must separate user functionality (including user interface
 services) from information system management functionality.'
 desc 'Separating user functionality from management
 functionality is a requirement for all the components within the container platform.
 Without the separation, users may have access to management functions that can
 degrade the container platform and the services being offered and can offer a method
 to bypass testing and validation of functions before introduced into a production
 environment. The separation should be enforced by each component within the
 container platform. This requirement also applies to Zero Trust
 initiatives.'
 desc 'check', 'Review the container platform configuration to determine if
 management functionality is separated from user functionality. Validate that the
 separation is also implemented within the components by trying to execute
 management functions for each component as a user. If the container platform is
 not configured to separate management and user functionality or if component
 management and user functionality are not separated, this is a finding.'
 desc 'fix', 'Configure the container platform and its components
 to separate management and user functionality.'
 impact 0.5
 tag check_id: 'C-36050r601742_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233114'
 tag rid: 'SV-233114r1137643_rule'
 tag stig_id: 'SRG-APP-000211-CTR-000530'
 tag gtitle: 'SRG-APP-000211'
 tag fix_id: 'F-36018r600830_fix'
 tag 'documentable'
 tag cci: ['CCI-001082']
 tag nist: ['SC-2']
 tag ksi:  ['KSI-IAM-JIT']
 tag nist_r4: ['SC-2']
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
