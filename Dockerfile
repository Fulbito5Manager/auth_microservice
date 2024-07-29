FROM openjdk:17-jdk-slim
ENV LANG C.UTF-8
ENV LC_ALL C.UTF-8
VOLUME /tmp
COPY target/tu-app.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java","-jar","/app.jar"]