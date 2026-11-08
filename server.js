const express=require('express'),fs=require('fs'),crypto=require('crypto');
const D=process.env.DATA_DIR||__dirname;require('fs').mkdirSync(D,{recursive:true});const F=D+'/db.json',app=express();
let db=fs.existsSync(F)?JSON.parse(fs.readFileSync(F)):{users:[],products:[],orders:[],faqs:[],settings:{brand:'DHANEY CHEATS',logo:'',whatsapp:'',bank:'',qr:{}}};
const R=process.env.SUPABASE_URL,K=process.env.SUPABASE_KEY,last={};
const sb=(path,o={})=>fetch(R+path,{...o,headers:{apikey:K,...(String(K).startsWith('eyJ')?{Authorization:'Bearer '+K}:{}),...o.headers}});
async function loadRemote(){const r=await sb('/rest/v1/kv?select=k,v');if(!r.ok)throw new Error('Supabase load failed '+r.status+' '+await r.text());(await r.json()).forEach(x=>{db[x.k]=x.v;last[x.k]=JSON.stringify(x.v)})}
let busy=false,again=false;
async function flush(){if(busy){again=true;return}busy=true;
 try{const rows=Object.keys(db).map(k=>({k,s:JSON.stringify(db[k])})).filter(x=>last[x.k]!==x.s);
  if(rows.length){const r=await sb('/rest/v1/kv',{method:'POST',headers:{'Content-Type':'application/json',Prefer:'resolution=merge-duplicates'},body:'['+rows.map(x=>'{"k":'+JSON.stringify(x.k)+',"v":'+x.s+'}').join(',')+']'});
   if(r.ok)rows.forEach(x=>last[x.k]=x.s);else console.log('SAVE FAILED',r.status,await r.text())}}catch(e){console.log('SAVE ERROR',e.message)}
 busy=false;if(again){again=false;flush()}}
const save=R?flush:()=>fs.writeFileSync(F,JSON.stringify(db));
const enc=encodeURIComponent;
async function keep(f){if(!R)return f;if(f.size>52428800){fs.unlink(f.path,()=>{});throw new Error('File too big for free storage (max 50 MB). Zip/compress it.')}
 const key=id()+id()+'-'+f.name.replace(/ /g,'_'),r=await sb('/storage/v1/object/files/'+enc(key),{method:'POST',headers:{'Content-Type':'application/octet-stream'},body:fs.readFileSync(f.path)});
 fs.unlink(f.path,()=>{});if(!r.ok)throw new Error('Storage upload failed: '+await r.text());return{name:f.name,size:f.size,key}}
async function rmStored(f){if(!f)return;if(f.key)await sb('/storage/v1/object/files/'+enc(f.key),{method:'DELETE'}).catch(()=>{});else fs.unlink(f.path,()=>{})}
const id=()=>crypto.randomBytes(6).toString('hex');
const hash=(p,s)=>crypto.scryptSync(p,s,64).toString('hex');
const mk=(name,email,pw,role)=>{const salt=id();return{id:id(),name,email:email.toLowerCase(),salt,hash:hash(pw,salt),role,created:Date.now()}};
const initAdmin=()=>{if(!db.users.some(u=>u.role=='admin')){const e=process.env.ADMIN_EMAIL||'admin@dhaney.local',pw=process.env.ADMIN_PASSWORD||crypto.randomBytes(5).toString('hex');db.users.push(mk('Admin',e,pw,'admin'));save();console.log('\n=== ADMIN LOGIN ===\nEmail:',e,'\nPassword:',pw,'\n(change by deleting db.json users or set ADMIN_EMAIL/ADMIN_PASSWORD before first run)\n')}};
const sess=new Map(),tries=new Map();
const UP=D+'/uploads';fs.mkdirSync(UP,{recursive:true});
function recv(req,res,done){if((+req.headers['content-length']||0)>1073741824)return res.status(413).json({error:'File too large (max 1GB)'});
 const name=decodeURIComponent(req.headers['x-filename']||'file').replace(/[^\w.\- ]/g,'_').slice(0,120),p=UP+'/'+id()+id(),w=fs.createWriteStream(p);
 req.pipe(w);w.on('finish',()=>done({name,path:p,size:fs.statSync(p).size}));w.on('error',()=>res.status(500).json({error:'Upload failed'}))}
app.use(express.json({limit:'12mb'}));
app.use((req,res,next)=>{res.set({'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'strict-origin-when-cross-origin'});
 const c=(req.headers.cookie||'').match(/sid=([a-f0-9]+)/);const uid=c&&sess.get(c[1]);req.user=uid&&db.users.find(u=>u.id==uid);req.sid=c&&c[1];next()});
const need=(req,res,next)=>req.user?next():res.status(401).json({error:'Login required'});
const adm=(req,res,next)=>req.user&&req.user.role=='admin'?next():res.status(403).json({error:'Forbidden'});
const me=u=>u&&{id:u.id,name:u.name,email:u.email,role:u.role,created:u.created};
app.set('trust proxy',1);
const login=(req,res,u)=>{const t=crypto.randomBytes(24).toString('hex');sess.set(t,u.id);res.set('Set-Cookie',`sid=${t}; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800${req.secure?'; Secure':''}`)};
app.post('/api/register',(req,res)=>{const{name,email,password}=req.body;
 if(!name||!/^\S+@\S+\.\S+$/.test(email||'')||(password||'').length<6)return res.status(400).json({error:'Enter name, valid email, password (6+ chars)'});
 if(db.users.some(u=>u.email==email.toLowerCase()))return res.status(400).json({error:'Email already registered'});
 const u=mk(String(name).slice(0,60),email,password,'user');db.users.push(u);save();login(req,res,u);res.json(me(u))});
app.post('/api/login',(req,res)=>{const k=req.ip,t=tries.get(k)||{n:0,at:Date.now()};if(Date.now()-t.at>9e5){t.n=0;t.at=Date.now()}
 if(t.n>=8)return res.status(429).json({error:'Too many attempts. Try later.'});
 const u=db.users.find(u=>u.email==String(req.body.email||'').toLowerCase());
 if(!u||hash(String(req.body.password||''),u.salt)!==u.hash){t.n++;tries.set(k,t);return res.status(400).json({error:'Wrong email or password'})}
 login(req,res,u);res.json(me(u))});
app.post('/api/logout',(req,res)=>{sess.delete(req.sid);res.set('Set-Cookie','sid=; Max-Age=0; Path=/');res.json({})});
app.get('/api/me',(req,res)=>res.json(me(req.user)||null));
app.get('/api/public',(req,res)=>res.json({settings:db.settings,products:db.products.map(({file,filePass,...p})=>({...p,hasFile:!!file})),faqs:db.faqs}));
app.post('/api/orders',need,(req,res)=>{const b=req.body,p=db.products.find(p=>p.id==b.productId);
 if(!p)return res.status(400).json({error:'Product not found'});
 if(p.maintenance)return res.status(400).json({error:'This product is under maintenance'});
 const v=(p.variants||[]).find(v=>v.label==b.variant);if((p.variants||[]).length&&!v)return res.status(400).json({error:'Select an option'});
 if(v&&v.out)return res.status(400).json({error:'This option is out of stock'});
 if(p.infoLabel&&!String(b.info||'').trim())return res.status(400).json({error:p.infoLabel+' is required'});
 if(!/^[0-9+\s-]{7,16}$/.test(b.whatsapp||''))return res.status(400).json({error:'Valid WhatsApp number required'});
 if(!['esewa','khalti','bank'].includes(b.method))return res.status(400).json({error:'Choose payment method'});
 const o={id:'DC-'+Date.now().toString(36).toUpperCase(),userId:req.user.id,productId:p.id,productName:p.name,img:p.img,variant:v?v.label:'',price:v?v.price:p.price,whatsapp:b.whatsapp,info:String(b.info||'').slice(0,200),infoLabel:p.infoLabel||'',method:b.method,proof:String(b.proof||'').slice(0,4e6),status:'pending',delivery:'',created:Date.now()};
 db.orders.push(o);save();res.json({id:o.id})});
app.get('/api/orders',need,(req,res)=>res.json(db.orders.filter(o=>o.userId==req.user.id).reverse().map(o=>{const p=db.products.find(p=>p.id==o.productId)||{},f=o.file||p.file,ok=o.status=='completed';return{...o,proof:undefined,file:undefined,delivery:ok?o.delivery:'',fileName:ok&&f?f.name:'',fileSize:ok&&f?f.size:0,filePass:ok&&f?(p.filePass||''):''}})));
app.get('/api/orders/:id/download',need,async(req,res)=>{const o=db.orders.find(o=>o.id==req.params.id);if(!o)return res.status(404).send('Not found');
 if(!(o.userId==req.user.id&&o.status=='completed')&&req.user.role!='admin')return res.status(403).send('Not allowed');
 const f=o.file||(db.products.find(p=>p.id==o.productId)||{}).file;if(!f)return res.status(404).send('No file');
 if(f.key){const r=await sb('/storage/v1/object/authenticated/files/'+enc(f.key));if(!r.ok)return res.status(404).send('File missing');res.set({'Content-Disposition':'attachment; filename="'+f.name+'"','Content-Type':'application/octet-stream'});return require('stream').Readable.fromWeb(r.body).pipe(res)}
 if(!fs.existsSync(f.path))return res.status(404).send('File missing');res.download(f.path,f.name)});
app.get('/api/admin/orders',adm,(req,res)=>res.json(db.orders.slice().reverse().map(o=>({...o,file:undefined,fileName:o.file?o.file.name:'',pFile:!!(db.products.find(p=>p.id==o.productId)||{}).file,user:(db.users.find(u=>u.id==o.userId)||{}).email}))));
app.put('/api/admin/orders/:id',adm,(req,res)=>{const o=db.orders.find(o=>o.id==req.params.id);if(!o)return res.status(404).json({});
 if(['pending','processing','completed','canceled'].includes(req.body.status))o.status=req.body.status;o.delivery=String(req.body.delivery||'').slice(0,5000);save();res.json({})});
app.put('/api/admin/products',adm,(req,res)=>{const p=req.body,cs=String(p.category||'GENERAL').split(',').map(s=>s.trim().toUpperCase()).filter(Boolean).slice(0,10);let x=db.products.find(a=>a.id==p.id);if(!x){x={id:id()};db.products.push(x)}
 Object.assign(x,{name:String(p.name||'').slice(0,100),category:cs[0]||'GENERAL',categories:cs.length?cs:['GENERAL'],price:+p.price||0,oldPrice:+p.oldPrice||0,imgs:(Array.isArray(p.imgs)&&p.imgs.filter(Boolean).length?p.imgs.filter(Boolean).slice(0,3):(x.imgs||[x.img].filter(Boolean))),maintenance:!!p.maintenance,popular:!!p.popular,infoLabel:String(p.infoLabel||'').slice(0,40),filePass:p.filePass?String(p.filePass).slice(0,200):(x.filePass||''),desc:String(p.desc||''),video:String(p.video||''),variants:(p.variants||[]).filter(v=>v.label).map(v=>({label:String(v.label),price:+v.price||0,out:!!v.out}))});x.img=(x.imgs||[])[0]||'';save();res.json({id:x.id})});
app.delete('/api/admin/products/:id',adm,(req,res)=>{db.products=db.products.filter(p=>p.id!=req.params.id);save();res.json({})});
app.put('/api/admin/faqs',adm,(req,res)=>{db.faqs=(req.body||[]).map(f=>({q:String(f.q||''),a:String(f.a||''),video:String(f.video||'')}));save();res.json({})});
app.put('/api/admin/settings',adm,(req,res)=>{Object.assign(db.settings,{brand:req.body.brand||'DHANEY CHEATS',logo:req.body.logo||'',whatsapp:req.body.whatsapp||'',bank:req.body.bank||'',qr:req.body.qr||{},social:Object.fromEntries(Object.entries(req.body.social||{}).filter(([k,v])=>/^https?:\/\//.test(v)).map(([k,v])=>[k,String(v).slice(0,300)]))});save();res.json({})});
app.get('/api/admin/users',adm,(req,res)=>res.json(db.users.map(me)));
app.put('/api/admin/products/:id/maintenance',adm,(req,res)=>{const p=db.products.find(p=>p.id==req.params.id);if(!p)return res.status(404).json({});p.maintenance=!!req.body.on;save();res.json({})});
app.get('/api/admin/backup',adm,(req,res)=>{res.set('Content-Disposition','attachment; filename=dhaney-backup-'+new Date().toISOString().slice(0,10)+'.json');res.type('json').send(JSON.stringify(db))});
app.get('/healthz',async(req,res)=>{if(R)await sb('/rest/v1/kv?select=k&limit=1').catch(()=>{});res.send('ok')});
const kinds={orders:()=>db.orders,products:()=>db.products};
app.post('/api/admin/:k(orders|products)/:id/file',adm,(req,res)=>{const o=kinds[req.params.k]().find(o=>o.id==req.params.id);if(!o)return res.status(404).json({error:'Not found'});
 recv(req,res,async f=>{try{await rmStored(o.file);o.file=await keep(f);save();res.json({name:f.name})}catch(e){res.status(400).json({error:e.message})}})});
app.delete('/api/admin/:k(orders|products)/:id/file',adm,(req,res)=>{const o=kinds[req.params.k]().find(o=>o.id==req.params.id);if(o&&o.file){rmStored(o.file);delete o.file;save()}res.json({})});
app.use(express.static(__dirname+'/public'));
(async()=>{if(R)await loadRemote();initAdmin();const srv=app.listen(process.env.PORT||3000,()=>console.log('Store running on http://localhost:'+(process.env.PORT||3000)+(R?' (online database)':' (local files)')));srv.requestTimeout=0})().catch(e=>{console.error('START FAILED:',e.message);process.exit(1)});
