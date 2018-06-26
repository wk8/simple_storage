# Simple storage

Toy Flask project to store & serve files.

Assuming you have python 3 installed and a reasonable version of `make` installed, you can run this project simply by running `make`.

Similary, run tests with `make test` and the linter with `make lint`.

## Example usage

```
curl -XPOST localhost:5000/register -H 'content-type: application/json' -d '{"username":"foo","password":"password"}'

curl -XPOST localhost:5000/login -H 'content-type: application/json' -d '{"username":"foo","password":"password"}'
# => {"token":"1cd9319132df46d097b290e8e0e2af851c1422a5db8a44d99a1be9bfe7c875c8"}

TOKEN=1cd9319132df46d097b290e8e0e2af851c1422a5db8a44d99a1be9bfe7c875c8

curl localhost:5000/files -H "x-session: $TOKEN"
# => []

curl -XPUT localhost:5000/files/happy_bunnies -H "x-session: $TOKEN" -H "content-type: jpg" --data-binary @test/fixtures/happy_bunnies.jpg

curl localhost:5000/files -H "x-session: $TOKEN"
# => ["happy_bunnies"]

curl localhost:5000/files/happy_bunnies -H "x-session: $TOKEN" > /tmp/happy_bunnies.jpg

diff test/fixtures/happy_bunnies.jpg /tmp/happy_bunnies.jpg
# => empty diff
```
