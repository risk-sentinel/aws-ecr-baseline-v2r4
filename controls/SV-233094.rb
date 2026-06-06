control 'SV-233094' do
  title 'The container platform must require the change of at least eight of the total
                number of characters when passwords are changed.'
  desc 'If the application allows the user to consecutively
                reuse extensive portions of passwords, this increases the chances of password
                compromise by increasing the window of opportunity for attempts at guessing and
                brute-force attacks. The number of changed characters refers to the number of
                changes required with respect to the total number of positions in the current
                password. In other words, characters may be the same within the two passwords;
                however, the positions of the like characters must be
                different.'
  desc 'check', 'Review the container platform configuration to determine if it
                    requires the change of at least eight of the total number of characters when
                    passwords are changed. If the container platform does not require the change of
                    at least eight of the total number of characters when passwords are changed,
                    this is a finding.'
  desc 'fix', 'Configure the container platform to require the
                change of at least eight of the total number of characters when passwords are
                changed.'
  impact 0.5
  tag check_id: 'C-36030r1107117_chk'
  tag severity: 'medium'
  tag gid: 'V-233094'
  tag rid: 'SV-233094r1107119_rule'
  tag stig_id: 'SRG-APP-000170-CTR-000430'
  tag gtitle: 'SRG-APP-000170'
  tag fix_id: 'F-35998r1107118_fix'
  tag 'documentable'
  tag cci: ['CCI-004066']
  tag nist: ['IA-5 (1) (h)']
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
