CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  clerk_user_id TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  full_name TEXT,
  role TEXT CHECK (role IN ('student', 'staff')) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE classes (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,              
  subject TEXT NOT NULL,             
  staff_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE students (
  id SERIAL PRIMARY KEY,
  user_id INT UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  class_id INT REFERENCES classes(id) ON DELETE SET NULL,
  roll_no TEXT UNIQUE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);



CREATE OR REPLACE FUNCTION check_staff_role()
RETURNS TRIGGER AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM users WHERE id = NEW.staff_id AND role = 'staff'
  ) THEN
    RAISE EXCEPTION 'Invalid staff_id: must have role = staff';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER ensure_staff_role
BEFORE INSERT OR UPDATE ON classes
FOR EACH ROW
EXECUTE FUNCTION check_staff_role();




CREATE OR REPLACE FUNCTION check_student_role()
RETURNS TRIGGER AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM users WHERE id = NEW.user_id AND role = 'student'
  ) THEN
    RAISE EXCEPTION 'Invalid user_id: must have role = student';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER ensure_student_role
BEFORE INSERT OR UPDATE ON students
FOR EACH ROW
EXECUTE FUNCTION check_student_role();



CREATE TABLE attendance_sessions (
  id SERIAL PRIMARY KEY,
  class_id INT NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
  session_code TEXT UNIQUE NOT NULL,   -- random/QR code
  created_at TIMESTAMPTZ DEFAULT NOW(),
  expires_at TIMESTAMPTZ DEFAULT (NOW() + INTERVAL '10 minutes') -- optional expiry
);


CREATE TABLE attendance_records (
  id SERIAL PRIMARY KEY,
  session_id INT NOT NULL REFERENCES attendance_sessions(id) ON DELETE CASCADE,
  student_id INT NOT NULL REFERENCES students(id) ON DELETE CASCADE,
  status TEXT DEFAULT 'present' CHECK (status IN ('present', 'absent')),
  marked_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(session_id, student_id)
);


CREATE INDEX idx_classes_staff_id ON classes(staff_id);
CREATE INDEX idx_students_class_id ON students(class_id);
CREATE INDEX idx_records_session_id ON attendance_records(session_id);
CREATE INDEX idx_records_student_id ON attendance_records(student_id);

SELECT *FROM users;



