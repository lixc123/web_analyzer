import { App } from 'antd'

/**
 * 使用App组件的notification hook，避免静态函数context警告
 */
export const useNotification = () => {
  const { notification } = App.useApp()
  return notification
}
