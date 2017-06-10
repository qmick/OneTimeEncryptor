#include "progress_delegate.h"
#include "progress_tablemodel.h"
#include <QProgressBar>
#include <QApplication>
#include <QDebug>

ProgressDelegate::ProgressDelegate()
{

}


void ProgressDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    if (index.column() == ProgressTableModel::ROW_PROGRESS)
    {
        int nProgress = index.data().toInt();
        QStyleOptionProgressBar  progressBarOption;
        progressBarOption.rect = option.rect;
        progressBarOption.minimum = 0;
        progressBarOption.maximum = 100;
        progressBarOption.progress = nProgress;
        progressBarOption.text = QString("%1%").arg(nProgress);
        progressBarOption.textVisible = true;
        QApplication::style()->drawControl(QStyle::CE_ProgressBar, &progressBarOption, painter);
    }
    else
    {
        QStyledItemDelegate::paint(painter, option, index);
    }
}
