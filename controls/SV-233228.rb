control 'SV-233228' do
  title 'The container platform must behave in a predictable and documented manner that
                reflects organizational and system objectives when invalid inputs are received.'
  desc 'Software or code parameters typically follow
                well-defined protocols that use structured messages (i.e., commands or queries) to
                communicate between software modules or system components. Structured messages can
                contain raw or unstructured data interspersed with metadata or control information.
                If attacker-supplied inputs to construct structured messages without properly
                encoding such messages, then the attacker could insert malicious commands or special
                characters that can cause the data to be interpreted as control information or
                metadata. This requirement guards against adverse or unintended system behavior
                caused by invalid inputs, where container platform components responses to the
                invalid input may be disruptive or cause the container image runtime to fail into an
                unsafe state. The behavior will be derived from the organizational and system
                requirements and includes, but is not limited to, notification of the appropriate
                personnel, creating an audit record, and rejecting invalid
                input.'
  desc 'check', 'Review the configuration to determine if the container platform
                    behaves in a predictable and documented manner that reflects organizational and
                    system objectives when invalid inputs are received. If the container platform
                    does not meet this requirement, this is a finding.'
  desc 'fix', 'Configure the container platform behave in a
                predictable and documented manner that reflects organizational and system objectives
                when invalid inputs are received.'
  impact 0.5
  tag check_id: 'C-36164r601821_chk'
  tag severity: 'medium'
  tag gid: 'V-233228'
  tag rid: 'SV-233228r961656_rule'
  tag stig_id: 'SRG-APP-000447-CTR-001100'
  tag gtitle: 'SRG-APP-000447'
  tag fix_id: 'F-36132r601172_fix'
  tag 'documentable'
  tag cci: ['CCI-002754']
  tag nist: ['SI-10 (3)']
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
