# Use a base image with Java 21
FROM eclipse-temurin:21-jdk-alpine

# Set the working directory inside the container
WORKDIR /app

# Copy the packaged jar file into the container
# Ensure you run 'mvn package' before building the image
ARG JAR_FILE=target/portfolio-0.0.1-SNAPSHOT.jar
COPY ${JAR_FILE} app.jar

# Expose the port the application runs on
EXPOSE 8080

# Command to run the application
ENTRYPOINT ["java", "-jar", "app.jar"]
