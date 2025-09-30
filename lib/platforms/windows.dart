import 'dart:io';
import 'package:bitsdojo_window/bitsdojo_window.dart';
import 'package:flutter/material.dart';

void setupWindowsWindow() {
  if (!Platform.isWindows) return;

  doWhenWindowReady(() {
    const initialSize = Size(1000, 700);
    appWindow.minSize = initialSize;
    appWindow.size = initialSize;
    appWindow.alignment = Alignment.center;
    appWindow.title = "Q-Safe Vault";
    appWindow.show();
  });
}

Widget wrapWithWindowsBorder(Widget child) {
  if (!Platform.isWindows) return child;

  return WindowBorder(
    color: Colors.blue,
    width: 1,
    child: Column(
      children: [
        WindowTitleBarBox(
          child: Row(
            children: [
              Expanded(child: MoveWindow()),
              WindowButtons(),
            ],
          ),
        ),
        Expanded(child: child),
      ],
    ),
  );
}

class WindowButtons extends StatelessWidget {
  final buttonColors = WindowButtonColors(
    iconNormal: Colors.white,
    mouseOver: Colors.blue[700],
    mouseDown: Colors.blue[900],
    iconMouseOver: Colors.white,
    iconMouseDown: Colors.white,
  );

  final closeButtonColors = WindowButtonColors(
    mouseOver: Colors.red,
    mouseDown: Colors.red[900],
    iconNormal: Colors.white,
    iconMouseOver: Colors.white,
  );

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        MinimizeWindowButton(colors: buttonColors),
        MaximizeWindowButton(colors: buttonColors),
        CloseWindowButton(colors: closeButtonColors),
      ],
    );
  }
}
