#include "mainwindow.h"
#include <QApplication>
#include <QPalette>
#include <QColor>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    // ----- Настройка черной темы -----
    QPalette darkPalette;

    // Основной фон
    darkPalette.setColor(QPalette::Window, QColor(53, 53, 53));
    darkPalette.setColor(QPalette::WindowText, Qt::white);

    // Фон виджетов
    darkPalette.setColor(QPalette::Base, QColor(42, 42, 42));
    darkPalette.setColor(QPalette::AlternateBase, QColor(66, 66, 66));
    darkPalette.setColor(QPalette::Text, Qt::white);
    darkPalette.setColor(QPalette::Button, QColor(53, 53, 53));
    darkPalette.setColor(QPalette::ButtonText, Qt::white);

    // Селекторы и выделение текста
    darkPalette.setColor(QPalette::Highlight, QColor(142, 45, 197));
    darkPalette.setColor(QPalette::HighlightedText, Qt::black);

    // Применяем палитру ко всему приложению
    a.setPalette(darkPalette);
    // ----------------------------------

    MainWindow w;
    w.show();
    return a.exec();
}
