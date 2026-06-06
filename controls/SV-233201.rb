control 'SV-233201' do
  title 'The container platform, for PKI-based authentication, must implement a local
                cache of revocation data to support path discovery and validation in case of the
                inability to access revocation information via network.'
  desc 'The potential of allowing access to users who are no
                longer authorized (have revoked certificates) increases unless a local cache of
                revocation data is
                configured.'
  desc 'check', 'Review the container platform configuration. If the container
                    platform is not implemented to use a local cache of revocation data to support
                    path discovery and validation in case of the inability to access revocation
                    information via network, this is a finding.'
  desc 'fix', 'Configure the container platform to implement a
                local cache of revocation data to support path discovery and validation in case of
                the inability to access revocation information via network.'
  impact 0.5
  tag check_id: 'C-36137r601805_chk'
  tag severity: 'medium'
  tag gid: 'V-233201'
  tag rid: 'SV-233201r981893_rule'
  tag stig_id: 'SRG-APP-000401-CTR-000965'
  tag gtitle: 'SRG-APP-000401'
  tag fix_id: 'F-36105r601091_fix'
  tag 'documentable'
  tag cci: ['CCI-004068']
  tag nist: ['IA-5 (2) (b) (2)']
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
