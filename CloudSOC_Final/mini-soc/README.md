# CloudSOC Engine (Mini SOC)

موقع فيه **جزئين منفصلين تماماً**:

| الجزء | اللينك | بيشوفه مين |
|---|---|---|
| **User Portal** (الـ honeypot) | `/login` | المهاجم / أي زائر. تصميم الـ neumorphic (كارت Login/Signup بيتقلب)، من غير أي لينك أو إشارة للأدمن |
| **SOC Admin Console** | `/admin/login` ثم `/admin/dashboard` و`/admin/blocked` | الفريق بس. تصميم داكن مختلف، لينكاته مفيش منها حاجة في صفحة المستخدم |

الكود كمان مفصول: `app/public.py` (المستخدم) و`app/admin.py` (الأدمن)، وكل واحد بقالبه وCSS بتاعه (`login.css` / `admin.css`).

## ملفات الفرونت
| الملف | وظيفته |
|---|---|
| `app/templates/login.html` | صفحة المستخدم (كان `index.html`) |
| `app/static/login.css` | تصميمها (كان `style.css`)، وفي آخره إضافات صفحات الخطأ |
| `app/static/login.js` | قلب الكارت وإظهار الباسورد (كان `script.js`) |
| `app/templates/public_base.html` | الهيكل المشترك: الخلفية والدوائر. وصفحة 403 و`error.html` بيستخدموه |

الفورم بيتبعت لـ `POST /login` بحقول `username` و`password`. نموذج التسجيل (Sign up) بيعرض رسالة "Registration is by invitation only" ومبيبعتش حاجة.

## تشغيل محلي (الأسهل)
**Windows:** اضغط دبل كليك على `run_local.bat`. هو بيجهز كل حاجة، وهيطلب منك مرة واحدة تكتب باسورد الأدمن (10 حروف أو أكتر). بعد كده افتح:
- المستخدم: http://127.0.0.1:5000/login
- الأدمن: http://127.0.0.1:5000/admin/login (Username: `admin` والباسورد اللي كتبته)

**Mac/Linux:** `./run_local.sh`

**يدوي:**
```
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
flask --app wsgi init-db
flask --app wsgi create-admin --username admin
flask --app wsgi run
```
> مفيش باسورد مكتوب في الكود ولا في أي صفحة. الأدمن بيتعمل بالأمر `create-admin` وبيتخزن مشفر بـ bcrypt.

## التجربة
1. افتح `/login` وجرب باسورد غلط **5 مرات** خلال دقيقتين ← المحاولة السادسة تدي **403** (الحظر يكون دقيقة في `run_local`، و15 دقيقة افتراضياً).
2. افتح `/admin/login` وادخل. **الأدمن بيفضل شغال حتى لو الـ IP بتاعك اتحظر** في صفحة المستخدم، لأن الحظر على الـ honeypot بس.
3. من `/admin/blocked` اعمل Unblock.

اختبار آلي: `python -m unittest tests.test_flow -v`

## الحماية المطبقة
- **Brute-force detection:** `MAX_FAILED_ATTEMPTS=5` خلال `ATTEMPT_WINDOW_SECONDS=120`.
- **Progressive ban:** 15 دقيقة ثم 30 ثم 60... (الأقصى `MAX_BAN_SECONDS`).
- **Rate limiting:** `LOGIN_RATE_LIMIT=10 per minute` على الـ honeypot (يرجع 429) و`5 per minute` على دخول الأدمن.
- **Logging:** JSON لكل حدث: `failed_login` و`ip_blocked` و`blocked_request` و`rate_limited` و`admin_login_failed`.
- الحالة كلها في **الداتابيز** (مش في الذاكرة)، فالحظر يشتغل على كل الـ instances ولا يضيع مع الـ restart.
- باسوردات المهاجم بتتخزن مخفية جزئياً، وكل بيانات المهاجم بتتعرض بـ `textContent`/Jinja autoescape (ضد XSS).
- CSRF على فورمات الأدمن، وSecurity Headers وCSP، وbcrypt.
- `PROXY_HOPS` بيحدد الـ IP الحقيقي خلف الـ ALB/Nginx، فالهيدر المزيف `X-Forwarded-For` ما يتصدقش.

## الأرقام الحقيقية للـ Evaluation
> الهجوم **على السيرفر بتاعكم بس**، ومن جهاز تحت سيطرتكم.
```
python scripts/brute_force_test.py --url http://<العنوان>/login --attempts 30
hydra -l admin -P rockyou.txt <العنوان> http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid" -t 4 -V
for i in $(seq 1 25); do curl -s -o /dev/null -w "%{http_code}\n" http://<العنوان>/login; done | sort | uniq -c
ab -n 20000 -c 100 http://<ALB-DNS>/login     # بعد رفع LOGIN_RATE_LIMIT مؤقتاً وWHITELIST_IPS للجهاز اللي بيجرب
```
لـ Auto Scaling: `stress-ng --cpu 2 --timeout 600` على instance وراقبوا الـ ASG.

## النشر على AWS (ملخص)
1. **Network:** VPC فيها 2 public subnets (ALB + EC2) و2 private subnets (RDS).
2. **Security Groups:** `alb-sg` (80/443 من الكل)، `app-sg` (80 من `alb-sg` فقط و22 من IP بتاعكم)، `db-sg` (3306 من `app-sg` فقط).
3. **RDS MySQL** (db.t3.micro، private) وdatabase اسمها `minisoc`.
4. **SSM Parameter Store (SecureString):** `/minisoc/SECRET_KEY` و`/minisoc/DATABASE_URL` و`/minisoc/ADMIN_PASSWORD`.
   مثال: `mysql+pymysql://user:PASS@<rds-endpoint>:3306/minisoc`
5. **IAM Role** للـ EC2: `CloudWatchAgentServerPolicy` + قراءة `/minisoc/*` فقط.
6. **Launch Template:** Ubuntu 22.04، t3.micro، الـ role، `app-sg`، و`deploy/user-data.sh` (عدلوا `REPO_URL` و`REGION`).
7. **Target Group** (health check على `/health`) + **ALB**، ثم **Auto Scaling Group** (min 1 / desired 2 / max 4، CPU = 50%).
8. شغلوا `deploy/cloudwatch-setup.sh` لعمل الـ metric filters والـ alarms وSNS.
9. **HTTPS:** بدومين + شهادة ACM على الـ ALB، وبعدها `SESSION_COOKIE_SECURE=true`.
10. **اختياري لكن مفيد:** قيّدوا مسار `/admin/*` على الـ ALB بقاعدة listener rule حسب IP الفريق.

`GeoLite2-Country.mmdb` (مجاني من MaxMind) في `GEOIP_DB_PATH` عشان الدول تظهر. من غيره بتظهر `Unknown`، والـ IPs المحلية بتظهر `Local/Private`.

## حدود معروفة (للـ Limitations)
- الـ rate limiter بيخزن العدّاد في ذاكرة كل instance. الحل: Redis (ElastiCache) عبر `RATELIMIT_STORAGE_URI`. الحظر نفسه مشترك.
- الحظر على مستوى التطبيق (L7)، والتطوير: AWS WAF أو Network ACL.
- مهاجم بـ IPs كتير (distributed) صعب يتكشف بعتبة لكل IP، ومستخدمين خلف NAT واحد ممكن يتأثروا.
- دخول الأدمن محمي بـ rate limit وbcrypt بس (مش مربوط بنظام الحظر). التطوير: MFA.
