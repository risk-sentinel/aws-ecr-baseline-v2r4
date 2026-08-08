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

 # Reverse resolution (#11): supply-chain artifacts whose subject digest is
 # not a current image here. Either the image was replaced and its signature
 # left behind, or the subject is a child manifest of a multi-arch Image
 # Index. Informational like the rest of this control — an orphan is
 # provenance metadata, not a compliance failure — but it must be VISIBLE,
 # because from the forward direction alone it is indistinguishable from
 # there being no signature at all.
 in_scope.sort.each do |name|
 aws_ecr_repository(repository_name: name).orphan_supply_chain_artifacts.each do |o|
 it("#{name} — orphaned supply-chain artifact #{o}") { expect(true).to eq true }
 end
 end
 end
 end
end
