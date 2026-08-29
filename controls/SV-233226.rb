control 'SV-233226' do
 title 'The container platform must maintain the confidentiality and integrity of
 information during preparation for transmission.'
 desc 'Information may be unintentionally or maliciously
 disclosed or modified during preparation for transmission within the container
 platform during aggregation, at protocol transformation points, and during container
 image runtime. These unauthorized disclosures or modifications compromise the
 confidentiality or integrity of the information. When transmitting data, the
 container platform components need to leverage transmission protection mechanisms,
 such as TLS, TLS VPNs, or
 IPsec.'
 desc 'check', 'Review the documentation and deployed configuration to determine if
 the container platform maintains the confidentiality and integrity of
 information during preparation before transmission. If the confidentiality and
 integrity are not maintained using mechanisms such as TLS, TLS VPNs, or IPsec
 during preparation before transmission, this is a finding.'
 desc 'fix', 'Configure the container platform to maintain the
 confidentiality and integrity of information using mechanisms such as TLS, TLS VPNs,
 or IPsec during preparation for transmission.'
 impact 0.5
 tag check_id: 'C-36162r601817_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233226'
 tag rid: 'SV-233226r961638_rule'
 tag stig_id: 'SRG-APP-000441-CTR-001090'
 tag gtitle: 'SRG-APP-000441'
 tag fix_id: 'F-36130r601166_fix'
 tag 'documentable'
 tag cci: ['CCI-002420']
 tag nist: ['SC-8 (2)']
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
