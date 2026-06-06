control 'SV-233206' do
  title "The container platform must audit non-local maintenance and diagnostic sessions'
                organization-defined audit events associated with non-local maintenance."
  desc 'To fully investigate an attack, it is important to
                understand the event and those events taking place during the same time period.
                Often, non-local administrative access and diagnostic sessions are not logged. These
                events are seen as only administrative functions and not worthy of being audited,
                but these events are important in any investigation and are a major tool for
                assessing and investigating
                attacks.'
  desc 'check', "Review the container platform to verify if the platform is auditing
                    non-local maintenance and diagnostic sessions' organization-defined audit
                    events. If the container platform is not auditing non-local maintenance and
                    diagnostic sessions' organization-defined audit events, this is a finding."
  desc 'fix', "Configure the container platform to audit non-local
                maintenance and diagnostic sessions' organization-defined audit events."
  impact 0.5
  tag check_id: 'C-36142r601807_chk'
  tag severity: 'medium'
  tag gid: 'V-233206'
  tag rid: 'SV-233206r961548_rule'
  tag stig_id: 'SRG-APP-000409-CTR-000990'
  tag gtitle: 'SRG-APP-000409'
  tag fix_id: 'F-36110r601106_fix'
  tag 'documentable'
  tag cci: ['CCI-002884']
  tag nist: ['MA-4 (1) (a)']
  tag implementation_status: 'inherited'
  tag inherited_from: 'aws-shared-responsibility'

  # AWS-managed container-platform layer (runtime/host/control-plane/crypto-module/audit-
  # infra). Evidence = the leveraged AWS FedRAMP/DoD authorization manifest; Skip (not a
  # vacuous pass) until the consumer configures leveraged_evidence_base/inherited_evidence_uri.
  ev = input('inherited_evidence_uri', value: '')
  ev = attestation_uri(:leveraged, 'aws-container-platform-authorization', ext: 'json') if ev.to_s.empty?
  max_age = input('leveraged_evidence_max_age_days', value: 365)
  impact 0.5
  if ev.to_s.empty?
    describe 'AWS-inherited authorization evidence' do
      skip 'inherited-from-aws: AWS-managed layer; set leveraged_evidence_base / inherited_evidence_uri to the AWS FedRAMP/DoD authorization manifest, or supply a SAF attestation.'
    end
  else
    doc = document_attestation(ev, max_age_days: max_age)
    describe "AWS authorization evidence (#{ev})" do
      it('exists')  { expect(doc.exists?).to eq(true) }
      it('current') { expect(doc.current?(max_age)).to eq(true) }
    end
  end
end
