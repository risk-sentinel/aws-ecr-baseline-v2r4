control 'SV-233123' do
  title 'The container platform must preserve any information necessary to determine the
                cause of the disruption or failure.'
  desc 'When a failure occurs within the container platform,
                preserving the state of the container platform and its components, along with other
                container services, helps to facilitate container platform restart and return to the
                operational mode of the organization with less disruption to mission essential
                processes. When preserving state, considerations for preservation of data
                confidentiality and integrity must be taken into
                consideration.'
  desc 'check', 'Review the container platform configuration to determine if
                    information necessary to determine the cause of a disruption or failure is
                    preserved. If the information is not preserved, this is a finding.'
  desc 'fix', 'Configure the container platform to preserve
                information necessary to determine the cause of the disruption or failure.'
  impact 0.5
  tag check_id: 'C-36059r600856_chk'
  tag severity: 'medium'
  tag gid: 'V-233123'
  tag rid: 'SV-233123r961125_rule'
  tag stig_id: 'SRG-APP-000226-CTR-000575'
  tag gtitle: 'SRG-APP-000226'
  tag fix_id: 'F-36027r600857_fix'
  tag 'documentable'
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
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
