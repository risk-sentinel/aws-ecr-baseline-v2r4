control 'SV-263601' do
 title 'The container platform must synchronize system clocks within and between systems
 or system components.'
 desc 'Time synchronization of system clocks is essential
 for the correct execution of many system services, including identification and
 authentication processes that involve certificates and time-of-day restrictions as
 part of access control. Denial of service or failure to deny expired credentials may
 result without properly synchronized clocks within and between systems and system
 components. Time is commonly expressed in Coordinated Universal Time (UTC), a modern
 continuation of Greenwich Mean Time (GMT), or local time with an offset from UTC.
 The granularity of time measurements refers to the degree of synchronization between
 system clocks and reference clocks, such as clocks synchronizing within hundreds of
 milliseconds or tens of milliseconds. Organizations may define different time
 granularities for system components. Time service can be critical to other security
 capabilities such as access control and identification and authentication depending
 on the nature of the mechanisms used to support the
 capabilities.'
 desc 'check', 'Verify the container platform is configured to synchronize system
 clocks within and between systems or system components. If the container
 platform is not configured to synchronize system clocks within and between
 systems or system components, this is a finding.'
 desc 'fix', 'Configure the container platform to synchronize
 system clocks within and between systems or system components.'
 impact 0.5
 tag check_id: 'C-67501r982476_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-263601'
 tag rid: 'SV-263601r982477_rule'
 tag stig_id: 'SRG-APP-000920-CTR-000320'
 tag gtitle: 'SRG-APP-000920'
 tag fix_id: 'F-67409r981942_fix'
 tag 'documentable'
 tag cci: ['CCI-004922']
 tag nist: ['SC-45']
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
