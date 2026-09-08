import { computeTaint, isLineTainted } from "./src/lib/taint";
import { RULES } from "./src/lib/injection";

const code = `
const express = require("express");
const ejs = require("ejs");
const app = express();

app.get("/users", (req, res) => {
  const name = req.query.name;
  const filter = \`(&(uid=\${name})(objectClass=person))\`;
  ldap.search(filter, cb);
  const dn = \`uid=\${req.body.user},ou=people,dc=corp\`;
  client.bind(dn, pw, cb);
});

app.get("/greet", (req, res) => {
  res.send(ejs.render(\`<h1>\${req.query.tpl}</h1>\`, {}));
});

app.get("/raw", async (req, res) => {
  const users = await prisma.$queryRawUnsafe(\`SELECT * FROM users WHERE id = \${req.params.id}\`);
  res.json(users);
});

app.get("/find", (req, res) => {
  db.user.findMany({ where: req.body });
});
`;

const lines = code.split("\n");
const taint = computeTaint(lines);

const checks: [string, number][] = [
  ["LDAP-001", 9],
  ["LDAP-002", 11],
  ["SSTI-002", 15],
  ["ORM-001", 19],
  ["ORM-002", 24],
];

for (const [id, lineNo] of checks) {
  const rule = RULES.find((r) => r.id === id)!;
  const line = lines[lineNo - 1];
  const patternHit = rule.pattern.test(line);
  const tainted = isLineTainted(line, taint);
  const safeHint = rule.safeHints?.find((h) => line.toLowerCase().includes(h.toLowerCase()));
  console.log(`${id} L${lineNo}: pattern=${patternHit} tainted=${tainted} safeHint=${safeHint ?? "-"} | ${line.trim().slice(0, 70)}`);
}