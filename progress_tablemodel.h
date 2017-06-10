#ifndef PROGRESS_TABLEMODEL_H
#define PROGRESS_TABLEMODEL_H

#include <QAbstractTableModel>


class ProgressTableModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    enum { ROW_FILENAME = 0, ROW_STATUS, ROW_SIZE, ROW_PROGRESS, ROW_REASON };
    QVector<QStringList> mdata;

    ProgressTableModel();

public:
    QStringList mheader;

    // QAbstractItemModel interface
    int rowCount(const QModelIndex &parent) const;
    int columnCount(const QModelIndex &parent) const;
    QVariant data(const QModelIndex &index, int role) const;
    Qt::ItemFlags flags(const QModelIndex &index) const;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const;
};

#endif // PROGRESS_TABLEMODEL_H
