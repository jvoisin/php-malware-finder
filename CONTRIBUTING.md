## Contributing

First off, thank you for considering contributing to php-malware-finder.

### 1. Where do I go from here?

If you've noticed a bug, an undetected sample or have a question,
[search the issue tracker](https://github.com/nbs-system/php-malware-finder/issues)
to see if someone else has already created a ticket. If not, go ahead and
[make one](https://github.com/nbs-system/php-malware-finder/issues/new)!

### 2. Fork & create a branch

If this is something you think you can fix,
then [fork php-malware-finder](https://help.github.com/articles/fork-a-repo) and
create a branch with a descriptive name.

A good branch name would be (where issue #325 is the ticket you're working on):

```sh
git checkout -b add_new_sample_wp_bruteforcer
```

### 3. Get the test suite running

Just type `make tests`, the testsuite will be run automatically.

### 6. Make a Pull Request

At this point, you should switch back to your master branch and make sure it's
up to date with our upstream master branch:

```sh
git remote add upstream git@github.com:nbs-system/php-malware-finder.git
git checkout master
git pull upstream master
```

Then update your feature branch from your local copy of master, and push it!

```sh
git checkout add_new_sample_wp_bruteforcer
git rebase master
git push --set-upstream origin add_new_sample_wp_bruteforcer
```

Finally, go to GitHub and [make a Pull Request](https://help.github.com/articles/creating-a-pull-request) :D

Travis CI will [run our test suite](https://travis-ci.org/nbs-system/php-malware-finder).
We care about quality, so your PR won't be merged until all tests are passing.

### 7. Keeping your Pull Request updated

If a maintainer asks you to "rebase" your PR, they're saying that a lot of code
has changed, and that you need to update your branch so it's easier to merge.

To learn more about rebasing in Git, there are a lot of [good](http://git-scm.com/book/en/Git-Branching-Rebasing)
[resources](https://help.github.com/articles/interactive-rebase) but here's the suggested workflow:

```sh
git checkout add_new_sample_wp_bruteforcer
git pull --rebase upstream master
git push --force-with-lease add_new_sample_wp_bruteforcer
```

### 8. Merging a PR (maintainers only)

A PR can only be merged into master by a maintainer if:

1. It is passing CI.
2. It has no requested changes.
3. It is up to date with current master.

Any maintainer is allowed to merge a PR if all of these conditions are met.

### 9. Shipping a release (maintainers only)

1. Make sure that all pending and mergeable pull requests are in
2. Make sure that the all the tests are passing, with `make tests`
3. Update the Debian changelog in `./debian/changelog` with `dch -i`
4. Commit the result
5. Create a tag for the release:

  ```sh
  git checkout master
  git pull origin master
  make tests
  git config user.signingkey 498C46FF087EDC36E7EAF9D445414A82A9B22D78
  git config user.email security@nbs-system.com
  git tag -s v$MAJOR.$MINOR.$PATCH -m "v$MAJOR.$MINOR.$PATCH"
  git push --tags
  ```

6. Build the debian package with `make deb`
7. Create the [release on github](https://github.com/nbs-system/php-malware-finder/releases)
8. Do the *secret release dance*
