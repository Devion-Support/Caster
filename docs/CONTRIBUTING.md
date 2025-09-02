# Contributing to Caster

First off, thanks for taking the time to contribute! 🎉

The following is a set of guidelines for contributing to Caster, which is hosted on GitHub. These are mostly guidelines, not rules. Use your best judgment, and feel free to propose changes to this document in a pull request.

## Code of Conduct

This project and everyone participating in it is governed by the [Caster Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to [project maintainers].

## How Can I Contribute?

### Reporting Bugs

This section guides you through submitting a bug report for Caster. Following these guidelines helps maintainers and the community understand your report, reproduce the behavior, and find related reports.

Before creating bug reports, please check [this list](#before-submitting-a-bug-report) as you might find out that you don't need to create one. When you are creating a bug report, please [include as many details as possible](#how-do-i-submit-a-good-bug-report). Fill out [the required template](ISSUE_TEMPLATE.md), the information it asks for helps us resolve issues faster.

> **Note:** If you find a **Closed** issue that seems like it is the same thing that you're experiencing, open a new issue and include a link to the original issue in the body of your new one.

#### Before Submitting A Bug Report

* **Check the [documentation](README.md)** for tips on troubleshooting.
* **Perform a [search](https://github.com/yoganataa/Caster/issues)** to see if the problem has already been reported. If it has **and the issue is still open**, add a comment to the existing issue instead of opening a new one.

#### How Do I Submit A (Good) Bug Report?

Bugs are tracked as [GitHub issues](https://guides.github.com/features/issues/). Create an issue and provide the following information by filling in [the template](ISSUE_TEMPLATE.md).

Explain the problem and include additional details to help maintainers reproduce the problem:

* **Use a clear and descriptive title** for the issue to identify the problem.
* **Describe the exact steps which reproduce the problem** in as many details as possible.
* **Provide specific examples to demonstrate the steps**. Include links to files or GitHub projects, or copy/pasteable snippets, which you use in those examples.
* **Describe the behavior you observed after following the steps** and point out what exactly is the problem with that behavior.
* **Explain which behavior you expected to see instead and why.**
* **Include screenshots and animated GIFs** which show you following the described steps and clearly demonstrate the problem.
* **If you're reporting that Caster crashed**, include a crash report with a stack trace from the operating system.

### Suggesting Enhancements

This section guides you through submitting an enhancement suggestion for Caster, including completely new features and minor improvements to existing functionality. Following these guidelines helps maintainers and the community understand your suggestion and find related suggestions.

Before creating enhancement suggestions, please check [this list](#before-submitting-an-enhancement-suggestion) as you might find out that you don't need to create one. When you are creating an enhancement suggestion, please [include as many details as possible](#how-do-i-submit-a-good-enhancement-suggestion). Fill in [the template](ISSUE_TEMPLATE.md), including the steps that you imagine you would take if the feature you're requesting existed.

#### Before Submitting An Enhancement Suggestion

* **Check the [documentation](README.md)** to see if the functionality already exists.
* **Perform a [search](https://github.com/yoganataa/Caster/issues)** to see if the enhancement has already been suggested. If it has, add a comment to the existing issue instead of opening a new one.

#### How Do I Submit A (Good) Enhancement Suggestion?

Enhancement suggestions are tracked as [GitHub issues](https://guides.github.com/features/issues/). Create an issue and provide the following information:

* **Use a clear and descriptive title** for the issue to identify the suggestion.
* **Provide a step-by-step description of the suggested enhancement** in as many details as possible.
* **Provide specific examples to demonstrate the steps**. Include copy/pasteable snippets which you use in those examples, as [Markdown code blocks](https://help.github.com/articles/markdown-basics/#multiple-lines).
* **Describe the current behavior** and **explain which behavior you expected to see instead** and why.
* **Include screenshots and animated GIFs** which help you demonstrate the steps or point out the part of Caster which the suggestion is related to.
* **Explain why this enhancement would be useful** to most Caster users.
* **List some other libraries or applications where this enhancement exists.**

### Your First Code Contribution

Unsure where to begin contributing to Caster? You can start by looking through these `beginner` and `help-wanted` issues:

* [Beginner issues][beginner] - issues which should only require a few lines of code, and a test or two.
* [Help wanted issues][help-wanted] - issues which should be a bit more involved than `beginner` issues.

Both issue lists are sorted by total number of comments. While not perfect, number of comments is a reasonable proxy for impact a given change will have.

### Pull Requests

The process described here has several goals:

- Maintain Caster's quality
- Fix problems that are important to users
- Engage the community in working toward the best possible Caster
- Enable a sustainable system for Caster's maintainers to review contributions

Please follow these steps to have your contribution considered by the maintainers:

1. Follow all instructions in [the template](PULL_REQUEST_TEMPLATE.md)
2. Follow the [styleguides](#styleguides)
3. After you submit your pull request, verify that all [status checks](https://help.github.com/articles/about-status-checks/) are passing <details><summary>What if the status checks are failing?</summary>If a status check is failing, and you believe that the failure is unrelated to your change, please leave a comment on the pull request explaining why you believe the failure is unrelated. A maintainer will re-run the status check for you. If we conclude that the failure was a false positive, then we will open an issue to track that problem with our status check suite.</details>

While the prerequisites above must be satisfied prior to having your pull request reviewed, the reviewer(s) may ask you to complete additional design work, tests, or other changes before your pull request can be ultimately accepted.

## Styleguides

### Git Commit Messages

* Use the present tense ("Add feature" not "Added feature")
* Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
* Limit the first line to 72 characters or less
* Reference issues and pull requests liberally after the first line
* When only changing documentation, include `[ci skip]` in the commit title

### Kotlin Styleguide

All Kotlin code must adhere to the [Kotlin Coding Conventions](https://kotlinlang.org/docs/coding-conventions.html):

* Use 4 spaces for indentation, not tabs
* Use camelCase for variable and function names
* Use PascalCase for class and interface names
* Use UPPER_SNAKE_CASE for constants
* Keep lines under 120 characters
* Use meaningful variable and function names
* Add KDoc documentation for public APIs

### C++ Styleguide

All C++ code must adhere to the [Google C++ Style Guide](https://google.github.io/styleguide/cppguide.html):

* Use 2 spaces for indentation, not tabs
* Use snake_case for variable and function names
* Use PascalCase for class and struct names
* Use UPPER_SNAKE_CASE for constants and macros
* Keep lines under 80 characters
* Use meaningful variable and function names
* Add comments for complex algorithms and functions

### Documentation Styleguide

* Use [Markdown](https://daringfireball.net/projects/markdown) for documentation
* Reference functions and variables using backticks: `functionName()`
* Use relative links when referencing files in the repository
* Keep documentation up to date with code changes

## Additional Notes

### Issue and Pull Request Labels

This section lists the labels we use to help us track and manage issues and pull requests.

[GitHub search](https://help.github.com/articles/searching-issues/) makes it easy to use labels for finding groups of issues or pull requests you're interested in.

The labels are loosely grouped by their purpose, but it's not required that every issue have a label from every group or that an issue can't have more than one label from the same group.

#### Type of Issue and Issue State

* `bug` - Issues that are bugs
* `enhancement` - Issues that are feature requests
* `documentation` - Issues that are documentation related
* `question` - Issues that are questions
* `help-wanted` - Issues that need help from the community
* `beginner` - Issues that are good for beginners
* `duplicate` - Issues that are duplicates of other issues
* `wontfix` - Issues that won't be fixed
* `invalid` - Issues that are invalid
* `more-information-needed` - Issues that need more information

#### Pull Request Labels

* `work-in-progress` - Pull requests that are not ready for review
* `needs-review` - Pull requests that need review
* `needs-changes` - Pull requests that need changes
* `ready-to-merge` - Pull requests that are ready to merge

Thank you for reading and contributing to Caster!