control 'SV-233193' do
  title 'The container platform must require users to reauthenticate when
                organization-defined circumstances or situations require reauthentication.'
  desc "Controlling user access is paramount in securing the
                container platform. During a user's access to the container platform, events may
                occur that change the user's access and which require reauthentication. For
                instance, if the capability to change security roles or escalate privileges is
                implemented, it is critical the user reauthenticate. In addition to the
                reauthentication requirements associated with change in security roles or privilege
                escalation, organizations may require reauthentication of individuals in other
                situations, including (but not limited to) the following circumstances: (i) When
                authenticators change; (ii) When roles change; (iii) When security categories of
                information systems change; (iv) When the execution of privileged functions occurs;
                (v) After a fixed period of time; or (vi) Periodically. Within the DOD, the minimum
                circumstances requiring reauthentication are privilege escalation and role
                changes."
  desc 'check', 'Review documentation and configuration to determine if the container
                    platform requires a user to reauthenticate when organization-defined
                    circumstances or situations are met. If the container platform does not meet
                    this requirement, this is a finding.'
  desc 'fix', 'Configure the container platform to require a user
                to reauthenticate when organization-defined circumstances or situations are met.'
  impact 0.5
  tag check_id: 'C-36129r601066_chk'
  tag severity: 'medium'
  tag gid: 'V-233193'
  tag rid: 'SV-233193r1050787_rule'
  tag stig_id: 'SRG-APP-000389-CTR-000925'
  tag gtitle: 'SRG-APP-000389'
  tag fix_id: 'F-36097r601067_fix'
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
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
