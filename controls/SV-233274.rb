control 'SV-233274' do
 title 'The container platform must be able to store and instantiate industry standard
 container images.'
 desc 'Monitoring the container images and containers during
 their lifecycle is important to guarantee the container platform is secure. To
 monitor the containers and images, security tools can be put in place. To fully
 utilize the security tools available, using images formatted in an industry standard
 format should be used. This allows the tools to fully understand the images and
 containers. One standard being worked on by industry leaders in the container space
 is the Open Container Initiative (OCI). This group is developing a standard
 container image
 format.'
 desc 'check', 'Review the container platform configuration and documentation to
 determine if the platform is configured to store and instantiate industry
 standard container images. If the container platform cannot instantiate industry
 standard container images, this is a finding.'
 desc 'fix', 'Enable the container platform to store and
 instantiate industry standard container image formats.'
 impact 0.5
 tag check_id: 'C-36210r601887_chk'
 tag severity: 'medium'
 tag gid: 'V-233274'
 tag rid: 'SV-233274r961863_rule'
 tag stig_id: 'SRG-APP-000516-CTR-001330'
 tag gtitle: 'SRG-APP-000516'
 tag fix_id: 'F-36178r601310_fix'
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
