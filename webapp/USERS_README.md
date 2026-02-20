# مستخدمي الويب / Web Users

## كلمات المرور (Passwords)

يجب تخزين كلمات المرور **كقيمة hash (PBKDF2-SHA256)** في `webapp/users.json` وعدم حفظ أي كلمة مرور نصية مكشوفة.

### إنشاء hash لكلمة مرور

من جذر المشروع (مع تفعيل البيئة الافتراضية إن وُجدت):

```bash
python3 -m webapp.hash_password
# يطلب منك إدخال كلمة المرور ثم يطبع الـ hash

# أو مباشرة:
python3 -m webapp.hash_password كلمة_المرور
```

انسخ المخرجات (تبدأ عادةً بـ `pbkdf2:sha256:...`) وضعها في `webapp/users.json` تحت مفتاح `password` للمستخدم.

### تهيئة users.json

1. أنشئ `webapp/users.json` بصيغة JSON للمستخدمين وأدوارهم (مثل `"admin"`).
2. ولّد hash لكلمة مرورك عبر الأمر أعلاه ثم ضعه في حقل `password` لكل مستخدم.

### الحماية والتحقق عند تسجيل الدخول

- يدعم التطبيق الحماية ضد تخمين كلمات المرور (قفل مؤقت `429 Too Many Requests` بعد 8 محاولات فاشلة خلال 5 دقائق) مع حماية CSRF وإدارة الجلسة الآمنة (`POST /logout`).
- يُوصى بإزالة أي كلمات مرور نصية قديمة فورًا؛ إذا وُجد إدخال نصي قديم سيعمل فقط للتوافق الخلفي لكنه غير آمن ويجب استبداله بـ hash.

---

## Web Users (English)

Store passwords as a **PBKDF2-SHA256 hash**, never in plain text. From the project root:

```bash
python3 -m webapp.hash_password
# prompts for password and prints hash

# or:
python3 -m webapp.hash_password your_password
```

Put the generated `pbkdf2:sha256:...` output into `webapp/users.json` under the user's `password` field. Legacy plain-text entries are strongly discouraged and should be migrated to hashes immediately. Failed login attempts are rate-limited (HTTP `429` after 8 failures per 5 minutes), and `/login` / `/logout` enforce per-session CSRF tokens.
