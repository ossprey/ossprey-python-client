# gh-action
GitHub Action for scanning your code for mawlare



# Testing

## Test locally

You can build and test this GH action locally by running:

```
docker build -t ossprey-scan .
/usr/bin/docker run --name ossprey-scan --label 2181ac --workdir /github/workspace --rm -e "INPUT_PACKAGE=/app/test/simple_math" -e "INPUT_REQUIREMENTS=true" -e "INPUT_PIPENV=false" -e "INPUT_GITHUB_COMMENTS" -e "INPUT_URL" -e "INPUT_DRY_RUN=false" -e "INPUT_VERBOSE=true" -e "API_KEY=$OSSPREY_API_KEY" -e "HOME" -v "/var/run/docker.sock":"/var/run/docker.sock" -v "/home/runner/work/_temp/_github_home":"/github/home" -v "/home/runner/work/_temp/_github_workflow":"/github/workflow" -v "/home/runner/work/_temp/_runner_file_commands":"/github/file_commands" -v "/home/runner/work/demo/demo":"/github/workspace" ossprey-scan
```