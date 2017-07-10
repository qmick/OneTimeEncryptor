#include "progress_tablemodel.h"

ProgressTableModel::ProgressTableModel()
{
    mheader = QStringList({ tr("Filename"), tr("Status"), tr("Size"), tr("Progress"), tr("Detail") });
}


int ProgressTableModel::rowCount(const QModelIndex &) const
{
    return mdata.size();
}



int ProgressTableModel::columnCount(const QModelIndex &) const
{
    return mheader.size();
}

QVariant ProgressTableModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid())
        return QVariant();
    if (role == Qt::DisplayRole)
    {
        int ncol = index.column();
        int nrow =  index.row();
        QStringList values = mdata.at(nrow);
        if (values.size() > ncol)
            return values.at(ncol);
        else
            return QVariant();
    }
    return QVariant();
}

Qt::ItemFlags ProgressTableModel::flags(const QModelIndex &index) const
{
    if (!index.isValid())
        return Qt::NoItemFlags;

    Qt::ItemFlags flag = QAbstractItemModel::flags(index);

    return flag;
}

QVariant ProgressTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (role == Qt::DisplayRole && orientation == Qt::Horizontal) {
        return mheader.at(section);
    }
    return QAbstractTableModel::headerData(section, orientation, role);
}
