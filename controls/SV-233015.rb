control 'SV-233015' do
 title 'The container platform must use TLS 1.2 or greater for secure container image
 transport from trusted sources.'
 desc 'The authenticity and integrity of the container image
 during the container image lifecycle is part of the overall security posture of the
 container platform. This begins with the container image creation and pull of a base
 image from a trusted source for child container image creation and the instantiation
 of the new image into a running service. If an insecure protocol is used during
 transmission of container images at any step of the lifecycle, a bad actor may
 inject nefarious code into the container image. The container image, when
 instantiated, then becomes a security risk to the container platform, the host
 server, and other containers within the container platform. To thwart the injection
 of code during transmission, a secure protocol (TLS 1.2 or newer) must be used.
 Further guidance on secure transport protocols can be found in NIST SP
 800-52.'
 desc 'check', 'Review the container platform configuration to verify that TLS 1.2 or
 greater is being used for secure container image transport from trusted sources.
 If TLS 1.2 or greater is not being used for secure container image transport,
 this is a finding.'
 desc 'fix', 'Configure the container platform to use TLS 1.2 or
 greater when components communicate internally or externally. The fix ensures that
 all communication components in the container platform are configured to utilize
 secure versions of TLS.'
 impact 0.5
 tag check_id: 'C-35951r600532_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233015'
 tag rid: 'SV-233015r960759_rule'
 tag stig_id: 'SRG-APP-000014-CTR-000035'
 tag gtitle: 'SRG-APP-000014'
 tag fix_id: 'F-35919r600533_fix'
 tag 'documentable'
 tag cci: ['CCI-000068']
 tag nist: ['AC-17 (2)']
 tag nist_r4: ['AC-17 (2)']
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
