const core = require('@actions/core');
const github = require('@actions/github');
const fs = require('fs');

const repoToken = core.getInput('repo-token');
const org = core.getInput('org-name');
const repos = core.getInput('repo-names');

const repoNames = repos.split(',');

const artifact = require('@actions/artifact');
const artifactClient = artifact.create();
const artifactName = `dependency-lists`;
let files = [];
const rootDirectory = '.'; // Also possible to use __dirname
const options = {
  continueOnError: false
};


let { graphql } = require('@octokit/graphql')
graphql = graphql.defaults({
  headers: {
    authorization: `token ${repoToken}`,
    Accept: 'application/vnd.github.hawkgirl-preview+json'
  }
});

DumpDependencies();

async function DumpDependencies() {

  for (const repo of repoNames) {
    //Begin get depencies for one repo
    let pagination = null;
    const query =
      `query ($org: String! $repo: String! $cursor: String){
      repository(owner: $org name: $repo) {
        name
        vulnerabilityAlerts(first: 100 after: $cursor) {
          pageInfo {
            hasNextPage
            endCursor
          }
          totalCount
          nodes {
            id
            securityAdvisory {
              ...advFields
            }
            securityVulnerability {
              package {
                ...pkgFields
              }
              vulnerableVersionRange
            }
            vulnerableManifestFilename
            vulnerableManifestPath
            vulnerableRequirements
          }
        }
      }
    }
    fragment advFields on SecurityAdvisory {
      ghsaId
      permalink
      severity
      description
      summary
    }
    fragment pkgFields on SecurityAdvisoryPackage {
      name
      ecosystem
    }`

    try {
      const outfile = `./${org}-${repo}-dependency-list.csv`;
      files.push(outfile);
      const lines = ['org,repo,package,ecosystem,summary,severity,permalink'];

      let hasNextPage = false
      do {
        const getVulnResult = await graphql({ query, org: org, repo: repo, cursor: pagination })
        hasNextPage = getVulnResult.repository.vulnerabilityAlerts.pageInfo.hasNextPage
        const vulns = getVulnResult.repository.vulnerabilityAlerts.nodes

        for (const vuln of vulns) {
          lines.push(`${org},${repo},${vuln.securityVulnerability.package.name},${vuln.securityVulnerability.package.ecosystem},"${vuln.securityAdvisory.summary}",${vuln.securityAdvisory.severity},${vuln.securityAdvisory.permalink}`)
        }

        if (hasNextPage) {
          pagination = getVulnResult.repository.vulnerabilityAlerts.pageInfo.endCursor
        }
      } while (hasNextPage);
      fs.writeFileSync(outfile, lines.join('\n'));
    } catch (error) {
      console.log('Request failed:', error.request)
      console.log(error.message)
    }
  }
  const uploadResponse = await artifactClient.uploadArtifact(artifactName, files, rootDirectory, options);
}
