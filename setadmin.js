const fs=require('fs'),crypto=require('crypto');
const [,,email,pw,name]=process.argv;
if(!email||!pw||pw.length<6){console.log('Usage: node setadmin.js you@gmail.com NewPassword "Your Name"');process.exit(1)}
const F=__dirname+'/db.json';if(!fs.existsSync(F)){console.log('db.json not found. Run npm start once first.');process.exit(1)}
const db=JSON.parse(fs.readFileSync(F));
if(db.users.some(u=>u.email==email.toLowerCase()&&u.role!='admin')){console.log('That email is already used by a customer.');process.exit(1)}
const u=db.users.find(u=>u.role=='admin'),salt=crypto.randomBytes(6).toString('hex');
u.email=email.toLowerCase();u.salt=salt;u.hash=crypto.scryptSync(pw,salt,64).toString('hex');if(name)u.name=name;
fs.writeFileSync(F,JSON.stringify(db));console.log('Admin updated. Login with:',u.email);