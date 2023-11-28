wrk.method="POST"
wrk.headers["Content-Type"] = "application/json"
wrk.body='{"user_id": 4}'

token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MDEyMzU0MDksIm9yaWdfaWF0IjoxNzAxMTQ5MDA5LCJ1c2VyX2lkIjo0fQ.S1KonO88LxQnhhg8RGp-Lr4JiK0rhHbJH2t5QKkQ7es"

function request()
   -- 发送带有查询参数的请求到指定的 URL
   return wrk.format(nil, "/user/profile?token=token"..token)
end