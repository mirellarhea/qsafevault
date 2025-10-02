import com.android.build.gradle.BaseExtension
import org.gradle.api.tasks.Delete
import org.gradle.kotlin.dsl.register
import org.gradle.kotlin.dsl.configure

allprojects {
    repositories {
        google()
        mavenCentral()
    }
}

val newBuildDir: Directory = rootProject.layout.buildDirectory.dir("../../build").get()
rootProject.layout.buildDirectory.value(newBuildDir)

subprojects {
    val newSubprojectBuildDir: Directory = newBuildDir.dir(project.name)
    project.layout.buildDirectory.value(newSubprojectBuildDir)
}

subprojects {
    project.evaluationDependsOn(":app")
}
subprojects {
    plugins.withId("com.android.library") {
        extensions.configure<BaseExtension>("android") {
            if (namespace.isNullOrBlank()) {
                namespace = "com.example.${project.name}"
            }
        }
    }
    plugins.withId("com.android.application") {
        extensions.configure<BaseExtension>("android") {
            if (namespace.isNullOrBlank()) {
                namespace = "com.example.${project.name}"
            }
        }
    }
}

tasks.register<Delete>("clean") {
    delete(rootProject.layout.buildDirectory)
}
