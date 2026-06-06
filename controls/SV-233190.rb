control 'SV-233190' do
 title 'All non-essential, unnecessary, and unsecure organization ports, protocols, and services
 must be disabled in the container platform.'
 desc 'To properly offer services to the user and to
 orchestrate containers, the container platform may offer services that use ports and
 protocols that best fit those services. The container platform, when offering the
 services, must only offer the services on ports and protocols authorized by the organization.
 To validate that the services are using only the approved ports and protocols, the
 organization must perform a periodic scan/review of the container platform and
 disable functions, ports, protocols, and services deemed to be unneeded or
 non-secure.'
 desc 'check', 'Review the container platform configuration to determine if services
 or capabilities presently on the information system are required for operational
 or mission needs. If additional services or capabilities are present on the
 system, this is a finding.'
 desc 'fix', 'Configure the container platform to only utilize
 secure ports and protocols required for operation that have been accepted for use as
 per the Ports, Protocols, and Services Category Assignments List (PPS baseline) from DISA
 (ports, protocols, and services (PPS) management).'
 impact 0.5
 tag check_id: 'C-36126r601057_chk'
 tag severity: 'medium'
 tag gid: 'V-233190'
 tag rid: 'SV-233190r961470_rule'
 tag stig_id: 'SRG-APP-000383-CTR-000910'
 tag gtitle: 'SRG-APP-000383'
 tag fix_id: 'F-36094r601058_fix'
 tag 'documentable'
 tag cci: ['CCI-001762']
 tag nist: ['CM-7 (1) (b)']
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
