control 'SV-233055' do
 title 'The container platform must use internal system clocks to generate audit record
 time stamps.'
 desc 'Understanding when and sequence of events for an
 incident is crucial to understand what may have taken place. Without a common clock,
 the components generating audit events could be out of synchronization and would
 then present a picture of the event that is warped and corrupted. To give a clear
 picture, it is important that the container platform and its components use a common
 internal
 clock.'
 desc 'check', 'Review the container platform configuration files to determine if the
 internal system clock is used for time stamps. If the container platform does
 not use the internal system clock to generate time stamps, this is a finding.'
 desc 'fix', 'Configure the container platform to use internal
 system clocks to generate time stamps for log records.'
 impact 0.5
 tag check_id: 'C-35991r600652_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233055'
 tag rid: 'SV-233055r960927_rule'
 tag stig_id: 'SRG-APP-000116-CTR-000235'
 tag gtitle: 'SRG-APP-000116'
 tag fix_id: 'F-35959r600653_fix'
 tag 'documentable'
 tag cci: ['CCI-000159']
 tag nist: ['AU-8 a']
 tag ksi:  ['KSI-MLA-OSM']
 tag nist_r4: ['AU-8 a']
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
