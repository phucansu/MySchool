# MySchool

Nền tảng hỗ trợ giảng dạy và học tập hiệu quả dành cho học sinh THPT, tích hợp Google Gemini để hỗ trợ hỏi đáp, phân tích kết quả, tạo đề và xây dựng lộ trình học tập cá nhân hóa.

## Tính năng

### Người dùng

- Làm bài kiểm tra theo môn học và khối lớp.
- Chế độ thi có đếm ngược và tự nộp khi hết giờ.
- Chế độ luyện tập không giới hạn thời gian.
- Xem điểm, đáp án sai, giải thích và phân tích kết quả bằng AI.
- Theo dõi điểm, cấp độ, streak và lịch sử làm bài.
- Xem bảng xếp hạng người dùng.
- Dark mode trên toàn bộ giao diện, tự lưu lựa chọn.

### Chatbot học tập

- Chatbot học tập dùng chung cho mọi môn học.
- Lưu 10 lượt hỏi đáp gần nhất theo tài khoản trên trình duyệt.
- Đồng bộ lịch sử giữa chatbot nổi và trang chatbot riêng.
- Hiển thị công thức toán học bằng KaTeX.

### Roadmap

- Gemini tạo lộ trình học tập cá nhân hóa trong 4 tuần.
- Phân tích hồ sơ khảo sát và các kết quả kiểm tra gần nhất.
- Lưu và xem lại tối đa 5 roadmap gần nhất.

### Quản trị

- Quản lý người dùng và đề thi.
- Tạo đề thủ công hoặc tạo tự động bằng Gemini.
- Quét câu hỏi từ PDF và DOCX.
- Dashboard thống kê và biểu đồ.

## Công nghệ

- Frontend: HTML5, CSS3, Vanilla JavaScript.
- Backend: Node.js, Express 5.
- Database: PostgreSQL (khuyến nghị Neon).
- AI: Google Gemini qua `@google/generative-ai`.
- Tài liệu: `pdf-parse`, `mammoth`, `multer`.
- Bảo mật: JWT, bcrypt, Helmet, rate limiting.
- Email (đặt lại mật khẩu): Resend.
- Hiển thị toán học: KaTeX. Biểu đồ Admin: Chart.js.

## Yêu cầu

- Node.js 18 trở lên.
- PostgreSQL (khuyến nghị [Neon](https://neon.tech/) cho môi trường serverless/Vercel).
- Gemini API key từ [Google AI Studio](https://aistudio.google.com/).

## Cài đặt

```bash
npm install
```

Sao chép `.env.example` thành `.env` và điền giá trị thật:

```bash
cp .env.example .env
```

Các biến môi trường:

| Biến | Bắt buộc | Mô tả |
|---|---|---|
| `NODE_ENV` | Khuyến nghị | `production` khi triển khai; để trống/`development` khi chạy local |
| `PORT` | Không | Cổng server local (mặc định 5000) |
| `DATABASE_URL` | Có (cloud) | Connection string PostgreSQL (Neon) |
| `DB_USER`/`DB_PASSWORD`/`DB_HOST`/`DB_PORT`/`DB_NAME` | Có (local) | Dùng khi không có `DATABASE_URL` |
| `JWT_SECRET` | **Có** | Server sẽ không khởi động nếu thiếu |
| `ADMIN_SECRET` | Không | Mã bí mật đăng ký admin; nếu không đặt, đăng ký admin bị vô hiệu |
| `GEMINI_API_KEY` | Có (AI) | Nguồn duy nhất cho key Gemini (không có UI lưu key) |
| `GOOGLE_CLIENT_ID` | Nếu bật Google Login | OAuth Client ID |
| `ALLOWED_ORIGINS` | Khuyến nghị (prod) | Danh sách origin cho CORS, phân tách bằng dấu phẩy |
| `RESEND_API_KEY` / `RESEND_FROM_EMAIL` | Nếu bật reset mật khẩu | Cấu hình gửi email qua Resend |
| `RESET_TOKEN_TTL_MINUTES` | Không | Thời hạn token reset (mặc định 30) |

> Không commit `.env` hoặc bất kỳ secret nào lên Git.

### Tạo secret mạnh

```bash
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
```

## Khởi tạo database

```bash
npm run setup-db
npm run migrate
```

Các bảng chính: `users`, `subjects`, `quizzes`, `questions`, `results`, `system_settings`, `topics`, `password_resets`.

## Chạy ứng dụng

```bash
npm start
```

Truy cập: `http://localhost:5000`

Các script:

```bash
npm start        # chạy server
npm run dev      # chạy server (dev)
npm run setup-db # tạo schema
npm run migrate  # migration bổ sung
npm run seed     # seed dữ liệu mẫu (DEV ONLY - không chạy ở production)
```

## Bảo mật

- Chấm điểm bài thi được thực hiện phía server (server là nguồn chân lý cho điểm số/leaderboard).
- Đặt lại mật khẩu dùng token một lần, có thời hạn, gửi qua email (Resend).
- Đăng nhập giả lập (mock) chỉ hoạt động ở môi trường development.
- Gemini API key chỉ đọc từ biến môi trường, không lưu trong database.

## Cấu hình Gemini

Đặt `GEMINI_API_KEY` trong biến môi trường. Đây là nguồn duy nhất; không có giao diện admin để nhập/lưu key.

## Triển khai Vercel

Dự án đã có `vercel.json`:

- `/api/*` chuyển tới `api/index.js`.
- File giao diện phục vụ từ `public/`.

Cấu hình các biến môi trường tương ứng trên Vercel (xem bảng ở trên). Database (Neon) nên tách khỏi Vercel để dễ chuyển provider.

## License

[MIT](LICENSE) © 2026 An Nguyễn
