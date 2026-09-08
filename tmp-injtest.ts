import { scan } from "./src/lib/scanner";

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

const pkg = `{"dependencies":{"pg":"8.11.0","express":"4.18.2"}}`;

const result = scan([
  { name: "routes.js", content: code },
  { name: "package.json", content: pkg },
]);
const deep = result.findings.filter((f) => ["LDAP-", "SSTI-", "ORM-"].some((p) => f.ruleId.startsWith(p)));
console.log("Deep-scan findings:", deep.length);
for (const f of deep) console.log(" -", f.ruleId, f.severity, `line ${f.line}:`, f.title);
const orm = deep.find((f) => f.ruleId === "ORM-001");
console.log("engine-aware payload tail:", orm?.payload.split("\n").slice(-2).join(" | "));
console.log("score:", result.score, "grade:", result.grade);
