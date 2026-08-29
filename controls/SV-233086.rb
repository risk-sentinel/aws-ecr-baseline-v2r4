control 'SV-233086' do
 title 'The container platform must uniquely identify all network-connected nodes before
 establishing any connection.'
 desc 'A container platform usually consists of multiple
 nodes. It is important for these nodes to be uniquely identified before a connection
 is allowed. Without identifying the nodes, unidentified or unknown nodes may be
 introduced, thereby facilitating malicious
 activity.'
 desc 'check', 'Review the container platform configuration to determine if the
 container platform uniquely identifies all nodes before establishing a
 connection. If the container platform is not configured to uniquely identify all
 nodes before establishing the connection, this is a finding.'
 desc 'fix', 'Configure the container platform to uniquely
 identify all nodes before establishing the connection.'
 impact 0.5
 tag check_id: 'C-36022r601720_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233086'
 tag rid: 'SV-233086r960999_rule'
 tag stig_id: 'SRG-APP-000158-CTR-000390'
 tag gtitle: 'SRG-APP-000158'
 tag fix_id: 'F-35990r600746_fix'
 tag 'documentable'
 tag cci: ['CCI-000778']
 tag nist: ['IA-3']
 tag nist_r4: ['IA-3']
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
