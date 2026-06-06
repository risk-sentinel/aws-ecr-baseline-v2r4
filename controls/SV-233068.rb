control 'SV-233068' do
  title 'The container platform must limit privileges to the container platform keystore.'
  desc 'The container platform keystore is used to store
                credentials used to build a trust between the container platform and some external
                source. This trust relationship is authorized by the organization. If a malicious
                user were to have access to the container platform keystore, two negative scenarios
                could develop: 1) Keys not approved could be introduced and 2) Approved keys
                deleted, leading to the introduction of container images from sources that were
                never approved by the organization. To thwart this threat, it is important to
                protect the container platform keystore and give access to only those individuals
                and roles approved by the
                organization.'
  desc 'check', 'Review the container platform keystore configuration to determine if
                    the level of access to the keystore is controlled through user privileges.
                    Attempt to perform keystore operations to determine if the privileges are
                    enforced. If the container platform keystore is not limited through user
                    privileges or the user privileges are not enforced, this is a finding.'
  desc 'fix', 'Configure the container platform to use and enforce
                user privileges when accessing the container platform keystore.'
  impact 0.5
  tag check_id: 'C-36004r601873_chk'
  tag severity: 'medium'
  tag gid: 'V-233068'
  tag rid: 'SV-233068r960960_rule'
  tag stig_id: 'SRG-APP-000133-CTR-000300'
  tag gtitle: 'SRG-APP-000133'
  tag fix_id: 'F-35972r600692_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
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
