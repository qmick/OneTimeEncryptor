#ifndef PROGRESSBAR_DELEGATE_H
#define PROGRESSBAR_DELEGATE_H

#include <QStyledItemDelegate>

class ProgressDelegate : public QStyledItemDelegate
{
    Q_OBJECT

public:
    ProgressDelegate();

    // QAbstractItemDelegate interface
public:
    void paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const;
};

#endif // PROGRESSBAR_DELEGATE_H
