# sfn

Secrets Fast Now is a shitty gitleaks port to C. It's wicked fast tho because of oniguruma and no GC? Who can say? Computers are magic. Lotta inspiration came from `ag`, the silver searcher. Code is messy, but so is my brain.

### Why did you make this? You should be adding features to gitleaks...

I wanted to write something in C.

### How do I run this?
```
git submodule init
git submodule update
make clean && make

./bin/sfn directory <path-to-target>

git log -p | ./bin/sfn stdin
```
### Can I use my old gitleaks config?
Kinda, you gotta make some changes though. Check out the config in this repo. Allowlists aren't implemented yet.

### Why no `git` command?
I have a branch attempting to do this using libgit2 and also piping `git log -p` in but performance isn't that impressive. If someone wants to contribute...sick.


