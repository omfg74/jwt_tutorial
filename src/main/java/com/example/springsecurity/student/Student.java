package com.example.springsecurity.student;

public class Student {

    private final Integer studentId;
    private final String studentName;

    public Student(Integer studentId, String studentNam) {
        this.studentId = studentId;
        this.studentName = studentNam;
    }


    public Integer getStudentId() {
        return studentId;
    }

    public String getStudentName() {
        return studentName;
    }

    @Override
    public String toString() {
        return "Student{" +
                "studentId=" + studentId +
                ", studentNam='" + studentName + '\'' +
                '}';
    }
}
