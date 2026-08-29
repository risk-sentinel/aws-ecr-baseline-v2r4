control 'SV-233019' do
 title 'The container platform must use a centralized user management solution to support
 account management functions.'
 desc "Enterprise environments make application account
 management challenging and complex. A manual process for account management
 functions adds the risk of a potential oversight or other error. A comprehensive
 application account management process that includes automation helps to ensure
 accounts designated as requiring attention are consistently and promptly addressed.
 Examples include, but are not limited to, using automation to take action on
 multiple accounts designated as inactive, suspended, or terminated or by disabling
 accounts located in non-centralized account stores, such as multiple servers. This
 requirement applies to all account types, including individual/user, shared, group,
 system, guest/anonymous, emergency, developer/manufacturer/vendor, temporary, and
 service. The application must be configured to automatically provide account
 management functions, and these functions must immediately enforce the
 organization's current account policy. The automated mechanisms may reside within
 the application itself or may be offered by the operating system or other
 infrastructure-providing automated account management capabilities. Automated
 mechanisms may be comprised of differing technologies, that when placed together,
 contain an overall automated mechanism supporting an organization's automated
 account management requirements. Account management functions include: assignment of
 group or role membership; identifying account type; specifying user access
 authorizations (i.e., privileges); account removal, update, or termination; and
 administrative alerts. The use of automated mechanisms can include: using email or
 text messaging to automatically notify account managers when users are terminated or
 transferred; using the information system to monitor account usage; or using
 automated telephonic notification to report atypical system account
 usage."
 desc 'check', 'Review the container platform to determine if it is using a
 centralized user management system for user management functions. If the
 container platform is not using a centralized user management system for user
 management functions, this is a finding.'
 desc 'fix', 'Configure the container platform to use a
 centralized user management system for user management functions.'
 impact 0.5
 tag check_id: 'C-35955r600544_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233019'
 tag rid: 'SV-233019r1043176_rule'
 tag stig_id: 'SRG-APP-000023-CTR-000055'
 tag gtitle: 'SRG-APP-000023'
 tag fix_id: 'F-35923r600545_fix'
 tag 'documentable'
 tag cci: ['CCI-000015']
 tag nist: ['AC-2 (1)']
 tag nist_r4: ['AC-2 (1)']
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
