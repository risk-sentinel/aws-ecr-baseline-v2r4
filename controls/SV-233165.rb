control 'SV-233165' do
  title 'The container platform must automatically lock an account until the locked
                account is released by an administrator when three unsuccessful login attempts in 15
                minutes are exceeded.'
  desc 'By limiting the number of failed login attempts, the
                risk of unauthorized system access via user password guessing, otherwise known as
                brute forcing, is reduced. Limits are imposed by locking the
                account.'
  desc 'check', 'Determine if the container platform is configured to automatically
                    lock an account until the locked account is released by an administrator when
                    three unsuccessful login attempts in 15 minutes are exceeded. If the container
                    platform is not configured to lock the account, this is a finding.'
  desc 'fix', 'Configure the container platform to automatically
                lock an account until the locked account is released by an administrator when three
                unsuccessful login attempts in 15 minutes are exceeded.'
  impact 0.5
  tag check_id: 'C-36101r601766_chk'
  tag severity: 'medium'
  tag gid: 'V-233165'
  tag rid: 'SV-233165r961368_rule'
  tag stig_id: 'SRG-APP-000345-CTR-000785'
  tag gtitle: 'SRG-APP-000345'
  tag fix_id: 'F-36069r600983_fix'
  tag 'documentable'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
  tag implementation_status: 'inherited'
  tag inherited_from: 'aws-shared-responsibility'

  # AWS-managed: IAM identity internals / Fargate runtime / platform config (FedRAMP/DoD ATO).
  ev = input('inherited_evidence_uri', value: '')
  ev = attestation_uri(:leveraged, 'aws-container-platform-authorization', ext: 'json') if ev.to_s.empty?
  max_age = input('leveraged_evidence_max_age_days', value: 365)
  impact 0.5
  if ev.to_s.empty?
    describe 'AWS-inherited authorization evidence' do
      skip 'inherited-from-aws: AWS-managed layer; set leveraged_evidence_base/inherited_evidence_uri to the AWS FedRAMP/DoD authorization manifest, or supply a SAF attestation.'
    end
  else
    doc = document_attestation(ev, max_age_days: max_age)
    describe "AWS authorization evidence (#{ev})" do
      it('exists') { expect(doc.exists?).to eq(true) }
      it('current') { expect(doc.current?(max_age)).to eq(true) }
    end
  end
end
