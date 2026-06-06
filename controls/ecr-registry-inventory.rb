# encoding: UTF-8

control 'ecr-registry-inventory' do
 impact 0.0
 title 'ECR registry inventory (informational)'
 desc "
 Enumerates every ECR repository in the account/region so the HDF records the full
 assessed registry surface, and flags which repositories are excluded from scoring
 via excluded_repositories input. Most organizations run more than one registry;
 the per-repository registry controls iterate this in-scope set and score each repo
 independently (pass/fail per repo).

 Informational only: impact 0.0 renders this Not Applicable in the HDF rollup — it is
 scope/provenance metadata, never a pass or fail.
 "
 tag scan_target: true
 tag implementation_status: 'inherited'

 all_repos = aws_ecr_repositories.repository_names
 excluded = excluded_repositories_list
 in_scope = ecr_repos_in_scope

 describe 'ECR registry inventory' do
 if all_repos.empty?
 it('no ECR repositories found in this account/region') { expect(true).to eq true }
 else
 it("repositories found = #{all_repos.length}; in scope = #{in_scope.length}; excluded = #{excluded.length}") do
 expect(true).to eq true
 end
 all_repos.sort.each do |name|
 flag = excluded.include?(name) ? ' [EXCLUDED]' : ''
 it("repository: #{name}#{flag}") { expect(true).to eq true }
 end
 end
 end
end
